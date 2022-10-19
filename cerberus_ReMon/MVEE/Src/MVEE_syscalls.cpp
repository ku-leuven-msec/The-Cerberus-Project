/*
 * Cerberus PKU-based Sandbox
 *
 * Check Cerberus/cerberus_ReMon/README.md for licensing terms.
 */

// *****************************************************************************
// This file implements the high-level syscall handling logic and implements
// syscall handlers for the "fake" syscalls we use in some of our
// synchronization agents (cfr. MVEE_fake_syscalls.h).
// *****************************************************************************

#include <memory>
#include <fcntl.h>
#include <cstring>
#include "MVEE.h"
#include "MVEE_monitor.h"
#include "MVEE_private_arch.h"
#include "MVEE_fake_syscall.h"
#include "MVEE_syscalls.h"
#include "MVEE_mman.h"
#include "MVEE_logging.h"
#include "MVEE_signals.h"
#include "MVEE_interaction.h"
#include "MVEE_numcalls.h"

/*-----------------------------------------------------------------------------
  handler and logger table
-----------------------------------------------------------------------------*/
#include "MVEE_syscall_handler_table.h"

/*-----------------------------------------------------------------------------
    call_resume - 
-----------------------------------------------------------------------------*/
void monitor::call_resume()
{
	if (!interaction::resume_until_syscall(variants[0].variantpid))
		throw ResumeFailure(0, "syscall resume");
}

/*-----------------------------------------------------------------------------
    call_resume_fake_syscall - 
-----------------------------------------------------------------------------*/
void monitor::call_resume_fake_syscall()
{
	// let the variants execute a dummy getpid syscall instead
	if (!interaction::write_syscall_no(variants[0].variantpid, __NR_getpid))
		throw RwRegsFailure(0, "set fake syscall no");

	if (!interaction::resume_until_syscall(variants[0].variantpid))
		throw ResumeFailure(0, "fake syscall resume");
}

/*-----------------------------------------------------------------------------
  pseudo handlers
-----------------------------------------------------------------------------*/
long monitor::handle_donthave(int variantnum) { return 0; }
long monitor::handle_dontneed(int variantnum) { return 0; }

/*-----------------------------------------------------------------------------
  log_donthave - This logger gets called if we don't have a specialized logger
  for the syscall we're executing
-----------------------------------------------------------------------------*/
void monitor::log_donthave(int variantnum)
{
	bool entry = (variants[variantnum].callnum != NO_CALL);

	if (entry) {
		const char* syscall_name = getTextualSyscall(variants[variantnum].callnum);
		if (strcmp(syscall_name, "sys_unknown") == 0) {
			debugf("%s - SYS_UNKNOWN - CALLNO: %ld (0x" PTRSTR ")\n", 
				   call_get_variant_pidstr().c_str(),
				   variants[variantnum].callnum,
				   variants[variantnum].callnum);
		}
		else {
			debugf("%s - %s(...)\n", 
				call_get_variant_pidstr().c_str(),
				mvee::upcase(syscall_name).c_str());
		}
	}
	else {
		debugf("%s - %s return: %ld\n", 
			   call_get_variant_pidstr().c_str(),
			   mvee::upcase(getTextualSyscall(variants[variantnum].prevcallnum)).c_str(),
			   call_postcall_get_variant_result()
			);
	}
}

void monitor::log_dontneed(int variantnum) 
{
	log_donthave(variantnum);
}

/*-----------------------------------------------------------------------------
    call_write_denied_syscall_return - 
-----------------------------------------------------------------------------*/
void monitor::call_write_denied_syscall_return()
{
	long err = variants[0].call_flags >> 6;
	if (variants[0].call_flags & MVEE_CALL_ERROR) {
		debugf("%s - %s forced return (error): %ld (%s)\n",
			   call_get_variant_pidstr().c_str(),
			   mvee::upcase(getTextualSyscall(variants[0].prevcallnum)).c_str(),
			   -err,
			   getTextualErrno(err));

		if (!interaction::write_syscall_return(variants[0].variantpid, (unsigned long) -err))
			throw RwRegsFailure(0, "write denied syscall error");
	}
	else {
		debugf("%s - %s forced return (value): %ld\n",
			   call_get_variant_pidstr().c_str(),
			   mvee::upcase(getTextualSyscall(variants[0].prevcallnum)).c_str(),
			   err);

		if (!interaction::write_syscall_return(variants[0].variantpid, err))
			throw RwRegsFailure(0, "write denied syscall return");
	}
}

/*-----------------------------------------------------------------------------
    call_precall_get_call_type - called at every syscall entrance. Determines
    whether or not a call is synchronized.
-----------------------------------------------------------------------------*/
unsigned char monitor::call_precall_get_call_type(long callnum)
{
	mvee_syscall_handler handler;
	unsigned char        result = MVEE_CALL_TYPE_NORMAL;

	call_grab_syslocks(callnum, MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_FULL);

	if (callnum >= 0 && callnum < MAX_CALLS) {
		handler = monitor::syscall_handler_table[callnum][MVEE_GET_CALL_TYPE];
		if (handler != MVEE_HANDLER_DONTHAVE && handler != MVEE_HANDLER_DONTNEED)
			result = ((this->*handler)(0) & 0xff);
	}
	else {
		// Handle fake calls
		switch(callnum) {
			case MVEE_INVOKE_LD:
			case MVEE_RUNS_UNDER_MVEE_CONTROL:
			case MVEE_JUMPS_SETUP:
			case MVEE_GET_SENSITIVE_INODE:
			case MVEE_SPECIAL_PAGE_SETUP:
			{
				result = MVEE_CALL_TYPE_UNSYNCED;
				break;
			}
		}
	}

	call_release_syslocks(callnum, MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_FULL);
	return result;
}

/*-----------------------------------------------------------------------------
    call_precall_log_args
-----------------------------------------------------------------------------*/
void monitor::call_precall_log_args(long callnum)
{
#ifndef MVEE_BENCHMARK
	mvee_syscall_logger logger;
	if (callnum >= 0 && callnum < MAX_CALLS)
		logger = monitor::syscall_logger_table[callnum][MVEE_LOG_ARGS];
	else
		logger = &monitor::log_donthave;

	(this->*logger)(0);
#endif
}

/*-----------------------------------------------------------------------------
    call_precall - called when the variants have reached the sync point at
    a synced call's entrance. Verifies if the call arguments match and decides
    how the call should be dispatched.
-----------------------------------------------------------------------------*/
long monitor::call_precall()
{
	long                 result = MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	long                 callnum;
	mvee_syscall_handler handler;

	// We already know that the syscall number matches so this is safe
	callnum = variants[0].callnum;
	call_grab_syslocks(callnum, MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_FULL);

	if (callnum >= 0 && callnum < MAX_CALLS) {
		handler                  = monitor::syscall_handler_table[callnum][MVEE_HANDLE_PRECALL];
		if (handler != MVEE_HANDLER_DONTHAVE && handler != MVEE_HANDLER_DONTNEED)
			result = (this->*handler)(-1);
	}

	if (result & MVEE_PRECALL_CALL_DENY)
		call_release_syslocks(callnum, MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_FULL);
	return result;
}

/*-----------------------------------------------------------------------------
    call_call_dispatch_unsynced - dispatches an unsynced call.
    unsynced syscalls don't have a precall handler so we grab the syslocks
    here and release them if the call doesn't really get dispatched
-----------------------------------------------------------------------------*/
long monitor::call_call_dispatch_unsynced()
{
	long                 result  = 0;
	mvee_syscall_handler handler;
	long                 callnum = variants[0].callnum;

	call_grab_syslocks(callnum, MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_FULL);
	if (callnum >= 0 && callnum < MAX_CALLS) {
		handler                  = monitor::syscall_handler_table[callnum][MVEE_HANDLE_CALL];
		if (handler != MVEE_HANDLER_DONTHAVE && handler != MVEE_HANDLER_DONTNEED)
			result = (this->*handler)(0);
#ifndef MVEE_BENCHMARK
		if (handler == MVEE_HANDLER_DONTHAVE)
			warnf("missing CALL handler for syscall: %lu (%s)\n", callnum, getTextualSyscall(callnum));
#endif
	}
	else {
		switch(callnum) {
			case MVEE_INVOKE_LD:
			{
#ifndef MVEE_BENCHMARK
				debugf("%s - Variant requested control transfer to manually mapped program interpreter\n", call_get_variant_pidstr().c_str());
#endif

				// force an munmap of the MVEE_LD_loader program - the loader is compiled
				// to always be at base address 0x08048000 regardless of ALSR
				unsigned long loader_base, loader_size;
				if (monitor::pmparser_get_ld_loader_bounds(loader_base, loader_size)) {
					if (!SETSYSCALLNO(0, __NR_munmap) ||
						!SETARG1(0, loader_base) ||
						!SETARG2(0, loader_size))
					{
						throw RwRegsFailure(0, "unmapping LD Loader");
					}
#ifndef MVEE_BENCHMARK
					debugf("%s - unmapping loader at: 0x" PTRSTR "-0x" PTRSTR "\n",
						   call_get_variant_pidstr().c_str(),
						   loader_base,
						   loader_base + loader_size);
#endif
				}
				break;
			}
			case MVEE_RUNS_UNDER_MVEE_CONTROL:
			{
				// syscall(MVEE_RUNS_UNDER_MVEE_CONTROL, NULL, &infinite_loop, NULL, NULL, NULL);
				// arguments:
				// void*          infinite_loop   : pointer to the infinite loop we're using for fast detaching/signal delivery
				variants[0].infinite_loop_ptr = ARG2(0);
				result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(1);
				break;
			}
			case MVEE_JUMPS_SETUP:
			{
				variants[0].syscall_jump = (void*)ARG1(0);
				variants[0].get_pku_domain_jump = (void*)ARG2(0);
				result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(0);
				break;
			}
			case MVEE_GET_SENSITIVE_INODE:
			{
				std::string str = "/proc/" + std::to_string(variants[0].variantpid) + "/mem";
				struct stat stats;
				stat(str.c_str(), &stats);
				result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(stats.st_ino);
				break;
			}
			case MVEE_SPECIAL_PAGE_SETUP:
			{
				variants[0].special_page = (void*)ARG1(0);
				result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(0);
				break;
			}
			default:
			{
				warnf("Don't have an unsynced call handler for call: %lu (%s)\n",
					  callnum, getTextualSyscall(callnum));
				result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(0);
				break;
			}
		}
	}

	if (result & MVEE_CALL_DENY)
		call_release_syslocks(callnum, MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_FULL);
	else
		call_release_syslocks(callnum, MVEE_SYSLOCK_PRECALL);
	return result;
}

/*-----------------------------------------------------------------------------
    call_call_dispatch - syslocks for synced calls are already taken in
    call_precall
-----------------------------------------------------------------------------*/
long monitor::call_call_dispatch()
{
	mvee_syscall_handler handler;
	long                 result  = 0;

	long                 callnum = variants[0].callnum;
	if (callnum >= 0 && callnum < MAX_CALLS) {
		handler = monitor::syscall_handler_table[callnum][MVEE_HANDLE_CALL];
		if (handler != MVEE_HANDLER_DONTHAVE && handler != MVEE_HANDLER_DONTNEED)
			result = (this->*handler)(-1);
#ifndef MVEE_BENCHMARK
		if (handler == MVEE_HANDLER_DONTHAVE)
			warnf("missing CALL handler for syscall: %ld (%s)\n", callnum, getTextualSyscall(callnum));
#endif
	}

	if (result & MVEE_CALL_DENY)
		call_release_syslocks(callnum, MVEE_SYSLOCK_FULL | MVEE_SYSLOCK_PRECALL);
	else
		call_release_syslocks(callnum, MVEE_SYSLOCK_PRECALL);
	return result;
}

/*-----------------------------------------------------------------------------
    call_postcall_log_return
-----------------------------------------------------------------------------*/
void monitor::call_postcall_log_return()
{
#ifndef MVEE_BENCHMARK
	mvee_syscall_logger logger;
	long callnum = variants[0].prevcallnum;
	if (callnum >= 0 && callnum < MAX_CALLS)
		logger = monitor::syscall_logger_table[callnum][MVEE_LOG_RETURN];
	else
		logger = &monitor::log_donthave;

	long result  = call_postcall_get_variant_result();
	bool success = call_check_result(result);

	if (!success) {
		debugf("%s - %s return: %ld (%s)\n",
			   call_get_variant_pidstr().c_str(),
			   mvee::upcase(getTextualSyscall(callnum)).c_str(),
			   result,
			   getTextualErrno(-result));
	}
	else {
		(this->*logger)(0);
	}
#endif
}

/*-----------------------------------------------------------------------------
    call_postcall_return_unsynced
-----------------------------------------------------------------------------*/
long monitor::call_postcall_return_unsynced()
{
	long                 result  = 0;
	mvee_syscall_handler handler;
	long                 callnum = variants[0].prevcallnum;

	call_grab_syslocks(callnum, MVEE_SYSLOCK_POSTCALL);
	if (callnum >= 0 && callnum < MAX_CALLS) {
		handler                  = monitor::syscall_handler_table[callnum][MVEE_HANDLE_POSTCALL];
		if (handler != MVEE_HANDLER_DONTHAVE && handler != MVEE_HANDLER_DONTNEED) {
			result = (this->*handler)(0);

			if (!(result & MVEE_POSTCALL_HANDLED_UNSYNCED_CALL)) {
				warnf("FIXME - TODO: POSTCALL handler for syscall %ld (%s) was not unsync-aware\n",
					  callnum, getTextualSyscall(callnum));
				shutdown(false);
			}
		}
#ifndef MVEE_BENCHMARK
		else if (handler == MVEE_HANDLER_DONTHAVE)
			warnf("missing POSTCALL handler for syscall: %ld (%s)\n", callnum, getTextualSyscall(callnum));
#endif
	}
	else {
		if (callnum == MVEE_INVOKE_LD) {
			unsigned long initial_stack = ARG1(0);
			unsigned long ld_entry      = ARG2(0);

#ifndef MVEE_BENCHMARK
			debugf("%s - munmap returned. Transfering control to program interpreter - entry point: 0x" PTRSTR " - initial stack pointer: 0x" PTRSTR "\n",
				   call_get_variant_pidstr().c_str(), ld_entry, initial_stack);
#endif

			SP_IN_REGS(variants[0].regs) = initial_stack;
			IP_IN_REGS(variants[0].regs) = ld_entry;
			if (!interaction::write_all_regs(variants[0].variantpid, &variants[0].regs))
				throw RwRegsFailure(0, "transfer control to interpreter");
		}
	}

	call_release_syslocks(callnum, MVEE_SYSLOCK_POSTCALL | MVEE_SYSLOCK_FULL);
	return result;
}

/*-----------------------------------------------------------------------------
    call_postcall_return
-----------------------------------------------------------------------------*/
long monitor::call_postcall_return()
{
	long                 result  = 0;
	mvee_syscall_handler handler;
	long                 callnum = variants[0].prevcallnum;

	call_grab_syslocks(callnum, MVEE_SYSLOCK_POSTCALL);
	if (callnum >= 0 && callnum < MAX_CALLS) {
		handler                  = monitor::syscall_handler_table[callnum][MVEE_HANDLE_POSTCALL];
		if (handler != MVEE_HANDLER_DONTHAVE && handler != MVEE_HANDLER_DONTNEED)
			result = (this->*handler)(-1);
#ifndef MVEE_BENCHMARK
		if (handler == MVEE_HANDLER_DONTHAVE)
			debugf("WARNING: missing POSTCALL handler for syscall: %ld (%s)\n", callnum, getTextualSyscall(callnum));
#endif
	}

	call_release_syslocks(callnum, MVEE_SYSLOCK_FULL | MVEE_SYSLOCK_POSTCALL);
	return result;
}

/*-----------------------------------------------------------------------------
    call_grab_locks - centralized lock management for system call handlers

    We enforce the following lock order:
      mman > sig > monitor > global
-----------------------------------------------------------------------------*/
void monitor::call_grab_locks(unsigned char syslocks)
{
	if (syslocks & MVEE_SYSLOCK_MMAN)
		set_mmap_table->grab_lock();
	if (syslocks & MVEE_SYSLOCK_SIG)
		set_sighand_table->grab_lock();
}

/*-----------------------------------------------------------------------------
    call_release_locks
-----------------------------------------------------------------------------*/
void monitor::call_release_locks(unsigned char syslocks)
{
	if (syslocks & MVEE_SYSLOCK_SIG)
		set_sighand_table->release_lock();
	if (syslocks & MVEE_SYSLOCK_MMAN)
		set_mmap_table->release_lock();
}

/*-----------------------------------------------------------------------------
    call_grab_syslocks
-----------------------------------------------------------------------------*/
void monitor::call_grab_syslocks(unsigned long callnum, unsigned char which)
{
	std::map<unsigned long, unsigned char>::iterator it = mvee::syslocks_table.find(callnum);
	if (it != mvee::syslocks_table.end()) {
		if (it->second & which)
			call_grab_locks(it->second);
	}
}

/*-----------------------------------------------------------------------------
    call_release_syslocks
-----------------------------------------------------------------------------*/
void monitor::call_release_syslocks(unsigned long callnum, unsigned char which)
{
	std::map<unsigned long, unsigned char>::iterator it = mvee::syslocks_table.find(callnum);
	if (it != mvee::syslocks_table.end()) {
		if (it->second & which)
			call_release_locks(it->second);
	}
}
