/*
 * Cerberus PKU-based Sandbox
 *
 * Check Cerberus/cerberus_ReMon/README.md for licensing terms.
 */

/*-----------------------------------------------------------------------------
  Includes
-----------------------------------------------------------------------------*/
#include <cerrno>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <linux/mman.h>
#include "MVEE.h"
#include "MVEE_monitor.h"
#include "MVEE_macros.h"
#include "MVEE_mman.h"
#include "MVEE_memory.h"
#include "MVEE_logging.h"
#include "MVEE_private_arch.h"
#include "MVEE_syscalls.h"
#include "MVEE_signals.h"
#include "MVEE_fake_syscall.h"
#include "MVEE_interaction.h"
#include "MVEE_erim.h"

/*-----------------------------------------------------------------------------
  sys_execve - (char* filename, char** argv, char** envp)
-----------------------------------------------------------------------------*/
// Fetching the execve arguments is very costly, especially without ptrace extensions.
// It must only be done once!
void monitor::handle_execve_get_args()
{
	set_mmap_table->mmap_execve_id = monitorid;
	unsigned int      argc = 0;
	unsigned int      envc = 0;

	std::stringstream args;
	std::stringstream envs;

	set_mmap_table->mmap_startup_info[0].argv.clear();
	set_mmap_table->mmap_startup_info[0].envp.clear();

	if (ARG2(0)) {
		while (true) {
			unsigned long argvp;

			if (!rw::read_primitive<unsigned long>(variants[0].variantpid,
												   (void*) (ARG2(0) + sizeof(long)*argc++), argvp) || argvp == 0)
			{
				argc--;
				break;
			}

			auto tmp = rw::read_string(variants[0].variantpid, (void*)argvp);
			if (tmp.length() > 0) {
				set_mmap_table->mmap_startup_info[0].argv.push_back(tmp);
				args << tmp << " ";
			}
		}
	}

	if (ARG3(0)) {
		while (true) {
			unsigned long envp;

			if (!rw::read_primitive<unsigned long>(variants[0].variantpid,
												   (void*) (ARG3(0) + sizeof(long)*envc++), envp) || envp == 0)
			{
				envc--;
				break;
			}

			auto tmp = rw::read_string(variants[0].variantpid, (void*)envp);
			if (tmp.length() > 0) {
				set_mmap_table->mmap_startup_info[0].envp.push_back(tmp);
				envs << tmp << " ";
			}
		}
	}

	set_mmap_table->mmap_startup_info[0].image = get_full_path(AT_FDCWD, (void*) ARG1(0));
	set_mmap_table->mmap_startup_info[0].serialized_argv = args.str();
	set_mmap_table->mmap_startup_info[0].serialized_envp = envs.str();
}

LOG_ARGS(execve)
{
	handle_execve_get_args();

	debugf("%s - SYS_EXECVE(PATH: %s -- ARGS: %s -- ENV: %s \n",
		   call_get_variant_pidstr().c_str(),
		   set_mmap_table->mmap_startup_info[0].image.c_str(),
		   set_mmap_table->mmap_startup_info[0].serialized_argv.c_str(),
		   set_mmap_table->mmap_startup_info[0].serialized_envp.c_str()
	);
}

PRECALL(execve)
{
	handle_execve_get_args();
	return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

CALL(execve)
{
	// check if the file exists first
	if (access(set_mmap_table->mmap_startup_info[0].image.c_str(), F_OK) == -1) {
		warnf("variant %d is trying to launch a non-existing program: %s\n", 0, set_mmap_table->mmap_startup_info[0].image.c_str());
		return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(ENOENT);
	}
#ifndef MVEE_BENCHMARK
	warnf("Executing variants: %s -- %s\n",
		  set_mmap_table->mmap_startup_info[0].image.c_str(),
		  set_mmap_table->mmap_startup_info[0].serialized_argv.c_str());
#endif

	// return immediately if we don't have to use the MVEE_LD_Loader
	if ((!(*mvee::config_variant_exec)["library_path"]
		 || (*mvee::config_variant_exec)["library_path"].asString().length() == 0))
		return MVEE_CALL_ALLOW;

	// check if we can load indirectly
	if (!mvee::os_can_load_indirect(set_mmap_table->mmap_startup_info[0].image)) {
		warnf("File %s is statically linked and position dependent. We will not be able to use Cerberus\n", set_mmap_table->mmap_startup_info[0].image.c_str());
		return MVEE_CALL_DENY;
	}

	rewrite_execve_args();

#ifdef ENABLE_ERIM_POLICY
	pkey_mprotect_count = 0;
	isolated_regions.clear();
#endif

	return MVEE_CALL_ALLOW;
}

POSTCALL(execve)
{
	if (call_succeeded) {
		// "During an execve(2), the dispositions of handled signals are
		// reset to the default; the dispositions of ignored signals are
		// left unchanged."
		set_sighand_table->reset();

		if (created_by_vfork) {
			created_by_vfork = false;

			std::shared_ptr<mmap_table> new_table = std::shared_ptr<mmap_table>(new mmap_table());
			call_release_syslocks(__NR_execve, MVEE_SYSLOCK_FULL);
			set_mmap_table.reset();
			set_mmap_table   = new_table;
			call_grab_syslocks(__NR_execve, MVEE_SYSLOCK_FULL);
		}

		variants[0].syscall_jump               = nullptr;
		variants[0].get_pku_domain_jump        = nullptr;
		variants[0].special_page               = nullptr;
		variants[0].first_syscall_after_execve = true;
#ifdef MVEE_CERBERUS_CP_PKU_SANDBOX_ENABLED
		// we want to start from a clean state at every execve
		clear_all_watches();
		set_mmap_table->active_dangerous_instructions.clear();
		set_mmap_table->active_executable_page_with_dangerous_instructions = 0;
		set_mmap_table->prot_non_exec_map.clear();

		// check for benign XRSTOR and WPKRU occurences
		// bool checks if it is an XRSTOR or not
		auto dangerous_instructions = pmparser_get_vdso_dangerous_instructions();
		if (dangerous_instructions.empty()) {
			debugf("[vdso] doesn't have explicit or implicit PKU-modifying instructions\n");
		}
		else {
			debugf("[vdso] has explicit or implicit PKU-modifying instructions\n");
			for (const auto& dangerous_instruction: dangerous_instructions)
				handle_dangerous_instruction(dangerous_instruction.first, dangerous_instruction.second, false);
		}
#endif
	}
	else {
		warnf("Could not start the variants (EXECVE error).\n");
		warnf("You probably forgot to compile the MVEE LD Loader. Please refer to MVEE/README.txt\n");
		shutdown(true);
	}

	call_release_syslocks(__NR_execve, MVEE_SYSLOCK_FULL);
	call_grab_syslocks(__NR_execve, MVEE_SYSLOCK_FULL);
	return 0;
}

/*-----------------------------------------------------------------------------
  sys_restart_syscall - (void)
-----------------------------------------------------------------------------*/
GET_CALL_TYPE(restart_syscall)
{
	return MVEE_CALL_TYPE_UNSYNCED;
}

/*-----------------------------------------------------------------------------
  sys_fork - (void)
-----------------------------------------------------------------------------*/
LOG_ARGS(fork)
{
	debugf("%s - SYS_FORK()\n", call_get_variant_pidstr().c_str());
}

PRECALL(fork)
{
	return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_FORK;
}

/*-----------------------------------------------------------------------------
  sys_vfork - (void)

  similar to fork but suspends the calling process until the child process
  terminates
-----------------------------------------------------------------------------*/
LOG_ARGS(vfork)
{
	debugf("%s - SYS_VFORK()\n", call_get_variant_pidstr().c_str());
}

PRECALL(vfork)
{
	return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_FORK;
}

/*-----------------------------------------------------------------------------
  sys_clone -

  The signature of this syscall function is distribution-specific.
  Ubuntu uses this version:

  man(2): (unsigned long clone_flags, void* child_stack, void* parent_tid, void*
  child_tid, struct pt_regs* regs)
  kernel: (unsigned long clone_flags, unsigned long child_stack, int*
  parent_tid, int* child_tid, int tls_val)
-----------------------------------------------------------------------------*/
LOG_ARGS(clone)
{
	debugf("%s - SYS_CLONE(%s)\n",
		   call_get_variant_pidstr().c_str(),
		   getTextualCloneFlags(ARG1(0)).c_str());
}

PRECALL(clone)
{
	return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_FORK;
}

/*-----------------------------------------------------------------------------
  sys_open -

  man(2): (const char* filename, int flags, mode_t mode)
  kernel: (const char* filename, int flags, umode_t mode)
-----------------------------------------------------------------------------*/
LOG_ARGS(open)
{
	auto str1 = rw::read_string(variants[0].variantpid, (void*)ARG1(0));

	debugf("%s - SYS_OPEN(%s, 0x%08X = %s, 0x%08X = %s)\n",
		   call_get_variant_pidstr().c_str(),
		   str1.c_str(),
		   (unsigned int)ARG2(0), getTextualFileFlags(ARG2(0)).c_str(),
		   (unsigned int)ARG3(0), getTextualFileMode(ARG3(0) & S_FILEMODEMASK).c_str());
}

CALL(open)
{
#ifdef MVEE_CERBERUS_CP_PKU_SANDBOX_ENABLED
	struct stat stats{};

	std::string sensitive_file = "/proc/" + std::to_string(variants[0].varianttgid) + "/mem";
	stat(sensitive_file.c_str(), &stats);
	unsigned long sensitive_inode = stats.st_ino;

	auto file = get_full_path(AT_FDCWD, (void*)ARG1(0));
	int ret = stat(file.c_str(), &stats);

	if (ret >= 0 /* the file may not exist */ && sensitive_inode == stats.st_ino) {
		debugf("The program is trying to open /proc/self/mem. This call has been denied.\n");
		return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
	}
#endif
	return MVEE_CALL_ALLOW;
}

/*-----------------------------------------------------------------------------
  sys_openat -

  man(2): (int dfd, const char *filename, int flags, mode_t mode)
  kernel: (int dfd, const char *filename, int flags, umode_t mode)
-----------------------------------------------------------------------------*/
LOG_ARGS(openat)
{
	auto filename = rw::read_string(variants[0].variantpid, (void*)ARG2(0));

	debugf("%s - SYS_OPENAT(%d, %s, 0x%08X (%s), 0x%08X (%s))\n",
		   call_get_variant_pidstr().c_str(),
		   (int)ARG1(0),
		   filename.c_str(),
		   (int)ARG3(0), getTextualFileFlags(ARG3(0)).c_str(),
		   (int)ARG4(0), getTextualFileMode(ARG4(0) & S_FILEMODEMASK).c_str());
}

CALL(openat)
{
#ifdef MVEE_CERBERUS_CP_PKU_SANDBOX_ENABLED
	struct stat stats{};

	std::string sensitive_file = "/proc/" + std::to_string(variants[0].varianttgid) + "/mem";
	stat(sensitive_file.c_str(), &stats);
	unsigned long sensitive_inode = stats.st_ino;

	auto file = get_full_path((unsigned long)(int)ARG1(0), (void*) ARG2(0));
	int ret = stat(file.c_str(), &stats);

	if (ret >= 0 && sensitive_inode == stats.st_ino) {
		debugf("The program is trying to open /proc/self/mem. This call has been denied.\n");
		return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
	}
#endif
	return MVEE_CALL_ALLOW;
}

/*-----------------------------------------------------------------------------
  sys_creat -

  man(2): (const char* pathname, mode_t mode)
  kernel: (const char* pathname, umode_t mode)
-----------------------------------------------------------------------------*/
LOG_ARGS(creat)
{
	auto str = rw::read_string(variants[0].variantpid, (void*)ARG1(0));

	debugf("%s - SYS_CREAT(%s, %d)\n",
		   call_get_variant_pidstr().c_str(),
		   str.c_str(),
		   (mode_t)ARG2(0));
}

CALL(creat)
{
#ifdef MVEE_CERBERUS_CP_PKU_SANDBOX_ENABLED
	struct stat stats{};

	std::string sensitive_file = "/proc/" + std::to_string(variants[0].varianttgid) + "/mem";
	stat(sensitive_file.c_str(), &stats);
	unsigned long sensitive_inode = stats.st_ino;

	auto file = get_full_path(AT_FDCWD, (void*)ARG1(0));
	int ret = stat(file.c_str(), &stats);

	if (ret >= 0 /* the file may not exist */ && sensitive_inode == stats.st_ino) {
		debugf("The program is trying to open /proc/self/mem. This call has been denied.\n");
		return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
	}
#endif
	return MVEE_CALL_ALLOW;
}

/*-----------------------------------------------------------------------------
  man(2) mmap: (void* addr, size_t len, int prot, int flags, int fd, off_t
  offset)
  kernel mmap: (unsigned long addr, unsigned long len, unsigned long prot,
  unsigned long flags, unsigned long fd, unsigned long pgoff)
-----------------------------------------------------------------------------*/
LOG_ARGS(mmap)
{
	debugf("%s - SYS_MMAP(0x" PTRSTR ", %lu, %s, %s, %d, %lu)\n",
		   call_get_variant_pidstr().c_str(),
		   (unsigned long)ARG1(0),
		   (unsigned long)ARG2(0),
		   getTextualProtectionFlags(ARG3(0)).c_str(),
		   getTextualMapType(ARG4(0)).c_str(),
		   (int)ARG5(0),
		   (unsigned long)ARG6(0));
}

CALL(mmap)
{
#ifdef MVEE_CERBERUS_CP_PKU_SANDBOX_ENABLED
	/* TODO race conditions may happen in case that we have multiple threads changing permissions and mapping code.
	 * This could lead to attacks similar to the ones described in PKU Pitfalls paper and/or monitor state.
	 *
	 * 1) Initially, we probably also want to map initially the region as non-executable and then change permissions with AJ in postcall handler
	 * 2) Stop World in multi-threading apps and update hw bps in all threads (difficult)
	 *    a. https://stackoverflow.com/questions/58503323/how-to-pause-all-threads-in-my-process-stop-the-world
	 *    b. https://codereview.stackexchange.com/questions/222451/suspend-and-resume-a-thread-using-signals
	 *    c. https://www.codeproject.com/Articles/570769/Data-Processing-Thread-with-the-Pause-Resume-Funct
	 * 3) Alternative, do not permit introduction of "new" dangerous instructions after we spawn new threads
	 */

	// check for executable and writable regions
	if ((ARG3(0) & PROT_EXEC) && (ARG3(0) & PROT_WRITE)) {
		debugf("Attempt to map a writable and executable region.\n");
#ifdef MVEE_DYNINST_BUGS_TREAT
		// this seems like a bug in older versions of dyninst
		debugf("We overwrite permissions to %s.\n", getTextualProtectionFlags(ARG3(0) & ~PROT_EXEC).c_str());
		call_overwrite_arg_value(3, ARG3(0) & ~PROT_EXEC, true);
		return MVEE_CALL_ALLOW;
#else
		shutdown(false);
		return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
#endif
	}
	// check for executable and non-private regions
	else if((ARG3(0) & PROT_EXEC) && (ARG4(0) & MAP_SHARED || (ARG4(0) & MAP_SHARED_VALIDATE) ==  MAP_SHARED_VALIDATE)) {
		debugf("Attempt to map a MAP_SHARED || MAP_SHARED_VALIDATE and executable region.\n");
		return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
	}

	// any file-backed region that can potentially become executable or is already executable (an mprotect can make a region executable and then it is too late)
	if (!(ARG4(0) & MAP_SHARED || (ARG4(0) & MAP_SHARED_VALIDATE) ==  MAP_SHARED_VALIDATE) && (int)ARG5(0) != -1) {
		if (variants[0].special_page) {
			MutexLock lock(&mvee::special_lock);
			std::string full_path    = get_path_from_fd(ARG5(0));
			std::string special_path = mvee::cerberus_create_special_file(full_path);
			if (special_path.length() + 1 > PAGE_SIZE) {
				warnf("We do not permit filenames larger than %lu bytes!!!\n", PAGE_SIZE);
				shutdown(false);
				return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
			}

			if (!special_path.empty()) {
				int special_fd = precall_open_special_fd(special_path);
				debugf("Create special fd %d for special file %s\n", special_fd, special_path.c_str());
				if (chmod(special_path.c_str(), S_IRUSR|S_IRGRP|S_IROTH) < 0) {
					warnf("We failed to do special file %s only-readable. Abort immediately!!!\n", special_path.c_str());
					shutdown(false);
					return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
				}

				call_overwrite_arg_value(5, special_fd, true);
			}
		}
	}
#endif
	return MVEE_CALL_ALLOW;
}

POSTCALL(mmap)
{
#ifdef MVEE_CERBERUS_CP_PKU_SANDBOX_ENABLED
	MutexLock lock(&mvee::special_lock);
	// even if we fail, we need to close the "special" file
	unsigned long real_fd;
	interaction::read_specific_reg(variants[0].variantpid, R8*8, real_fd);
	if (real_fd != ARG5(0)) {
		debugf("Detection of special fd %d. We need to close it.\n", (int)real_fd);
		postcall_close_special_fd(real_fd);
	}
#endif

	if (call_succeeded) {
#ifdef MVEE_CERBERUS_CP_PKU_SANDBOX_ENABLED
		/* TODO race conditions may happen in case that we have multiple threads changing permissions and mapping code.
		 * This could lead to attacks similar to the ones described in PKU Pitfalls paper and/or monitor state.
		 *
		 * Check call handler of map
		 */

		unsigned long result = call_postcall_get_variant_result();

#ifdef MVEE_DYNINST_BUGS_TREAT
		// normally this call would be denied ... if it does not then we are in a special dyninst case
		if ((ARG3(0) & PROT_EXEC) && (ARG3(0) & PROT_WRITE)) {
			return 0;
		}
#endif

		// Code for vetting non-benign WPKRU and XRSTOR instructions.
		if (ARG3(0) & PROT_EXEC) {
			std::string path = get_path_from_fd(ARG5(0));
			struct stat sb{};

			// if no backing file or special file ... may need to add more files like that here
			// these are not dangerous cases:
			//    MAP_ANONYMOUS | MAP_PRIVATE regions are initialized to 0
			//    special files like /dev/zero will never contain dangerous instructions
			if (path.empty() || path == std::string("/dev/zero") || path == std::string("/dev/null") || stat(path.c_str(), &sb) < 0) {
				debugf("mmap \"special\" file or anonymous region\n");
				goto OUT;
			}

			// Search for the word "beyond" in the following links to understand what is happening here:
			//   https://docs.oracle.com/cd/E88353_01/html/E37841/mmap-2.html
			//   https://www.ibm.com/support/knowledgecenter/ssw_ibm_i_74/apis/mmap.htm
			//   https://man7.org/linux/man-pages/man2/mmap.2.html
			//
			// Any reference to addresses beyond the end of the object will result in the delivery of a SIGBUS or SIGSEGV signal
			// !!! This is important !!!
			if ((unsigned long)sb.st_size < ARG6(0)) { // yeah we even find cases like this :(
				debugf("\"Really special\" case in mmap, where offset is bigger than the file's size\n");
				goto OUT;
			}

			/* we should only reach here if it is a regular file and offsets are fine */
			// check man pages why that is here
			unsigned long len                 = ROUND_UP(ARG2(0), PAGE_SIZE);
			unsigned long correct_len         = MIN(sb.st_size - ARG6(0), len);
			char*         buf                 = new(std::nothrow) char[correct_len];

			// Seems that we are unable to read XOM memory of the variant using process_vm_read
			if (ARG3(0) & PROT_READ) {
				if (!interaction::read_memory(variants[0].variantpid, (void*)result, correct_len, buf))
					throw RwMemFailure(0, "Failed to read contents of area that is mapped in the variant in postcall handler of mmap");
			}
			else {
				if (!interaction::read_memory_ptrace(variants[0].variantpid, (void*)result, correct_len, buf))
					throw RwMemFailure(0, "Failed to read contents of area that is mapped in the variant in postcall handler of mmap");
			}

			/* "regular" dangerous instructions */
			// check for XRSTOR and WPKRU occurrences
			// bool checks if it is an XRSTOR or not
			auto offsets = erim_memScanRegion(ERIM_UNTRUSTED_PKRU, buf, correct_len, path.empty() ? "[anonym*]" : path.c_str());

#ifdef CHECK_IF_INSTRUCTION_EMULATIONS_IS_NEEDED
			if (is_program_multithreaded() && !offsets.empty()) {
				warnf("Need to integrate the emulation engine here\n");
			}
#endif

			for (const auto& offset: offsets) {
				// take the actual virtual address that needs to be vetted
				unsigned long address_of_dangerous_instruction = result + offset.first;
				handle_dangerous_instruction(address_of_dangerous_instruction, offset.second, false);
			}

			/* "partial" dangerous instructions */
			// check for XRSTOR and WPKRU across region boundaries
			// partial dangerous instructions are non-benign. Domain switch gates are not designed that way.
			auto partial_dangerous_instructions = pmparser_get_partial_dangerous_instructions_of_a_region(nullptr,
																										   buf, correct_len,
																										   (void*)result,
																										   correct_len == len,
																										   ONLY_EXEC,
																										   ONLY_EXEC);

#ifdef CHECK_IF_INSTRUCTION_EMULATIONS_IS_NEEDED
			if (is_program_multithreaded() && !partial_dangerous_instructions.empty()) {
				warnf("Need to integrate the emulation engine here\n");
			}
#endif

			for (const auto& partial_dangerous_instruction: partial_dangerous_instructions)
				handle_dangerous_instruction(partial_dangerous_instruction.first, partial_dangerous_instruction.second, false);

			SAFEDELETEARRAY(buf);
		}
#endif
	}

#ifdef MVEE_CERBERUS_CP_PKU_SANDBOX_ENABLED
OUT:
#endif

	return 0;
}

LOG_RETURN(mmap)
{
	debugf("%s - SYS_MMAP return: 0x" PTRSTR "\n",
		   call_get_variant_pidstr().c_str(),
		   call_postcall_get_variant_result());
}

/*-----------------------------------------------------------------------------
  sys_munmap - 

  man(2): (void* addr, size_t length)
  kernel: (unsigned long addr, size_t length)
-----------------------------------------------------------------------------*/
LOG_ARGS(munmap)
{
	debugf("%s - SYS_MUNMAP(0x" PTRSTR ", %zd)\n", 
		   call_get_variant_pidstr().c_str(),
		   (unsigned long)ARG1(0),
		   (size_t)ARG2(0));
}

CALL(munmap)
{
#ifdef MVEE_CERBERUS_CP_PKU_SANDBOX_ENABLED
	// Protect special page
	if (variants[0].special_page) {
		if ((unsigned long)variants[0].special_page >= (unsigned long)ARG1(0)
			&& (unsigned long)variants[0].special_page < (unsigned long)ARG1(0) + ROUND_UP(ARG2(0), PAGE_SIZE))
		{
			warnf("Attempt to munmap the special page ... you are funny\n");
			return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
		}
	}

	// Protect syscall jump page
	if (variants[0].syscall_jump) {
		if ((unsigned long)variants[0].syscall_jump >= (unsigned long)ARG1(0)
			&& (unsigned long)variants[0].syscall_jump < (unsigned long)ARG1(0) + ROUND_UP(ARG2(0), PAGE_SIZE))
		{
			warnf("Attempt to munmap the syscall jump page ... you are funny\n");
			return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
		}
	}

	// we want to remove "vetting" of dangerous instructions
	variants[0].pending_dangerous_addresses.clear(); // this may be needed in case that a previous mprotect call failed, and we did not clear our data structure
	variants[0].pending_dangerous_addresses = monitor::get_deleted_dangerous_instructions((void*)ARG1(0), ARG2(0));
#endif
	return MVEE_CALL_ALLOW;
}

POSTCALL(munmap)
{
	if (call_succeeded) {
#ifdef MVEE_CERBERUS_CP_PKU_SANDBOX_ENABLED
		/* TODO race conditions may happen in case that we have multiple threads changing permissions and mapping code
		 * This could lead to attacks similar to the ones described in PKU Pitfalls paper and/or monitor state.
		 *
		 * Maybe need to check in handle_hw_bp_event_v1 and handle_hw_bp_event_v2, if the instruction is actually
		 * an hw bp or if it has been removed by another thread.
		 */

		// !!! this is a corner case !!!
		// An application could munmap or make non-executable a page that was made non-executable by Cerberus
		// In this case then we need to update our bookkeeping
		// Note: We do not need to change permissions ourselves ... the application would munmap it or change permissions
		auto it = set_mmap_table->prot_non_exec_map.begin();
		while (it != set_mmap_table->prot_non_exec_map.end()) {
			if ((unsigned long)ARG1(0) <= it->first && it->first < (unsigned long)ARG1(0) + (unsigned long)ROUND_UP(ARG2(0), PAGE_SIZE))
				it = set_mmap_table->prot_non_exec_map.erase(it);
			else
				++it;
		}

		for (const auto& pending_dangerous_instruction: variants[0].pending_dangerous_addresses)
			handle_dangerous_instruction(pending_dangerous_instruction.first, pending_dangerous_instruction.second, true);
		variants[0].pending_dangerous_addresses.clear();
#endif
	}

	return 0;
}

/*-----------------------------------------------------------------------------
  sys_mremap -

  man(2): (void* old_addr, size_t old_len, size_t new_len, int flags, ...)
  kernel: (unsigned long old_addr, unsigned long old_len, unsigned long new_len,
  unsigned long flags, unsigned long new_addr)
-----------------------------------------------------------------------------*/
LOG_ARGS(mremap)
{
	debugf("%s - SYS_MREMAP(OLD_ADDR=0x" PTRSTR ", OLD_LEN=%lu, NEW_LEN=%lu, FLAGS=%lu (%s), NEW_ADDR=0x" PTRSTR ")\n",
		   call_get_variant_pidstr().c_str(),
		   (unsigned long)ARG1(0),
		   (unsigned long)ARG2(0),
		   (unsigned long)ARG3(0),
		   (unsigned long)ARG4(0), getTextualMremapFlags(ARG4(0)),
		   (unsigned long)ARG5(0));
}

POSTCALL(mremap)
{
	if (call_succeeded) {
		// unmap target pages
		// TODO need to change that
		/*unsigned long new_address = call_postcall_get_variant_result();
		mmap_region_info* info = set_mmap_table->get_region_info(ARG1(0), ARG2(0));
		if (info) {
			auto new_region = new(std::nothrow) mmap_region_info(*info);

			if (new_region) {
				new_region->region_base_address = new_address;
				new_region->region_size         = ARG3(0);

				set_mmap_table->munmap_range(ARG1(0), ARG2(0));
				set_mmap_table->munmap_range(new_address, ARG3(0));
				set_mmap_table->insert_region(new_region);
			}
		}
		else {
			warnf("remap range not found: 0x" PTRSTR "-0x" PTRSTR "\n", (unsigned long)ARG1(0), (unsigned long)(ARG1(0) + ARG2(0)));
			shutdown(false);
		}*/
	}

	return 0;
}

LOG_RETURN(mremap)
{
	debugf("%s - SYS_MREMAP return: 0x" PTRSTR "\n",
		   call_get_variant_pidstr().c_str(),
		   (unsigned long)call_postcall_get_variant_result());
}

/*-----------------------------------------------------------------------------
  sys_mprotect - 

  man(2): (void* start, size_t len, int prot)
  kernel: (unsigned long start, size_t len, unsigned long prot)

  Unfortunately, it appears that this function must be synced. MMAP2 has a
  tendency to align new regions to existing bordering regions with the same
  protection flags. This behaviour CAN cause problems if we do not sync
  mprotect.
-----------------------------------------------------------------------------*/
LOG_ARGS(mprotect)
{
	debugf("%s - SYS_MPROTECT(0x" PTRSTR ", %zd, " PTRSTR " = %s)\n",
		   call_get_variant_pidstr().c_str(),
		   (unsigned long)ARG1(0),
		   (size_t)ARG2(0),
		   (unsigned long)ARG3(0),
		   getTextualProtectionFlags(ARG3(0)).c_str());
}

CALL(mprotect)
{
#ifdef MVEE_CERBERUS_CP_PKU_SANDBOX_ENABLED
	/* TODO race conditions may happen in case that we have multiple threads changing permissions and mapping code
	 * This could lead to attacks similar to the ones described in PKU Pitfalls paper and/or monitor state.
	 *
	 * 1) We need to put hw bps before we execute the system call and then remove them in case that we fail
	 * 2) In a multi-threaded app if the region is writable, we should make it non-writable before we scan (another thread may write something)
	 * 3) Stop world in multi-threading apps and update hw bps in all threads (difficult)
	 *
	 * Alternative, do not permit introduction of "new" dangerous instructions after we spawn new threads
	 */

	// Protect special page
	if (variants[0].special_page) {
		if ((unsigned long)variants[0].special_page >= (unsigned long)ARG1(0)
			&& (unsigned long)variants[0].special_page < (unsigned long)ARG1(0) + ROUND_UP(ARG2(0), PAGE_SIZE))
		{
			warnf("Attempt to change permissions of the special page ... you are funny\n");
			return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
		}
	}

	// Protect syscall jump page
	if (variants[0].syscall_jump) {
		if ((unsigned long)variants[0].syscall_jump >= (unsigned long)ARG1(0)
			&& (unsigned long)variants[0].syscall_jump < (unsigned long)ARG1(0) + ROUND_UP(ARG2(0), PAGE_SIZE))
		{
			warnf("Attempt to change permissions of the syscall jump page ... you are funny\n");
			return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
		}
	}

//#ifdef ENABLE_ERIM_POLICY
// This is redundant ... it does not affect the safe region that was protected using pkey_mprotect
//	if (!isolated_regions.empty()) {
//		for (auto pair: isolated_regions) {
//			if (is_region_included((void*)pair.first, ROUND_UP(pair.second, PAGE_SIZE), (void*)ARG1(0), ROUND_UP(ARG2(0), PAGE_SIZE))) {
//				warnf("Attempt to change permissions of isolated regions (ERIM_POLICY)\n");
//				return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
//			}
//		}
//	}
//#endif

#ifdef ENABLE_XOM_SWITCH_POLICY
	if (pmparser_is_xom_switch_policy_violated((void*)ARG1(0), ARG2(0), ARG3(0))) {
		warnf("Attempt to change permissions of XOM (XOM_SWITCH_POLICY)\n");
		return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
	}
#endif

	if ((ARG3(0) & PROT_EXEC) && (ARG3(0) & PROT_WRITE)) {
		debugf("Attempt to make a writable and executable region.\n");
#ifdef MVEE_DYNINST_BUGS_TREAT
		// this seems like a bug in older versions of dyninst
		debugf("We overwrite permissions to %s.\n", getTextualProtectionFlags(ARG3(0) & ~PROT_EXEC).c_str());
		call_overwrite_arg_value(3, ARG3(0) & ~PROT_EXEC, true);
		return MVEE_CALL_ALLOW;
#else
		return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
#endif
	}

	// in this case we want to add "vetting" of dangerous instructions
	if (ARG3(0) & PROT_EXEC) {
		// !!! this is a corner case !!!
		// An application could make again executable a page that was made non-executable by Cerberus
		// In this case then we need to update our bookkeeping
		auto it = set_mmap_table->prot_non_exec_map.begin();
		while (it != set_mmap_table->prot_non_exec_map.end()) {
			if ((unsigned long)ARG1(0) <= it->first && it->first < (unsigned long)ARG1(0) + (unsigned long)ROUND_UP(ARG2(0), PAGE_SIZE))
				it = set_mmap_table->prot_non_exec_map.erase(it);
			else
				++it;
		}

		variants[0].pending_dangerous_addresses.clear(); // this may be needed in case that a previous mprotect call failed, and we did not clear our data structure
		// Problem 1: Find all the normal "active" and "inactive" dangerous instructions in this area
		variants[0].pending_dangerous_addresses = monitor::pmparser_get_dangerous_instructions((void*)ARG1(0), ARG2(0), true, EVERYTHING);
		// Problem 2: Find all the partial "active" and "inactive" dangerous instructions in this area
		auto pending_partial_pending_dangerous_addresses = pmparser_get_partial_dangerous_instructions((void*)ARG1(0), ARG2(0), EVERYTHING, EVERYTHING);
		variants[0].pending_dangerous_addresses.insert(pending_partial_pending_dangerous_addresses.begin(), pending_partial_pending_dangerous_addresses.end());

#ifdef CHECK_IF_INSTRUCTION_EMULATIONS_IS_NEEDED
		if (is_program_multithreaded() && !pending_partial_pending_dangerous_addresses.empty()) {
			warnf("Need to integrate the emulation engine here\n");
		}
#endif

		// we care only about the "new" dangerous instructions ... for the other ones we have already done something
		for(const auto& dangerous_instruction: set_mmap_table->active_dangerous_instructions)
			variants[0].pending_dangerous_addresses.erase(dangerous_instruction);
	}
	// in this case we want to remove "vetting" of dangerous instructions
	else {
		variants[0].pending_dangerous_addresses.clear(); // this may be needed in case that a previous mprotect call failed, and we did not clear our data structure
		variants[0].pending_dangerous_addresses = monitor::get_deleted_dangerous_instructions((void*)ARG1(0), ARG2(0));
	}
#endif

// TODO this should be removed at some point
#ifdef MVEE_SUPPORTS_PKU_DOMAINS
	warnf("Domain value is %x\n", precall_get_pku_domain());
#endif

	return MVEE_CALL_ALLOW;
}

LOG_RETURN(mprotect)
{
	debugf("%s - SYS_MPROTECT return: %ld\n", 
		   call_get_variant_pidstr().c_str(),
		   call_postcall_get_variant_result());
}

POSTCALL(mprotect)
{
	if (call_succeeded) {
#ifdef MVEE_CERBERUS_CP_PKU_SANDBOX_ENABLED
		/* TODO race conditions may happen in case that we have multiple threads changing permissions and mapping code
		 * This could lead to attacks similar to the ones described in PKU Pitfalls paper and/or monitor state.
		 *
		 * check call of mprotect
		 */

#ifdef MVEE_DYNINST_BUGS_TREAT
		// normally this call would be denied ... if it does not then we are in a special dyninst case
		if ((ARG3(0) & PROT_EXEC) && (ARG3(0) & PROT_WRITE))
			return 0;
#endif

		if (!(ARG3(0) & PROT_EXEC)) {
			// !!! this is a corner case !!!
			// An application could munmap or make non-executable a page that was made non-executable by Cerberus
			// In this case then we need to update our bookkeeping
			// Note: We do not need to change permissions ourselves ... the application would munmap it or change permissions
			auto it = set_mmap_table->prot_non_exec_map.begin();
			while (it != set_mmap_table->prot_non_exec_map.end()) {
				if ((unsigned long)ARG1(0) <= it->first && it->first < (unsigned long)ARG1(0) + (unsigned long)ROUND_UP(ARG2(0), PAGE_SIZE))
					it = set_mmap_table->prot_non_exec_map.erase(it);
				else
					++it;
			}
		}

		// addresses of dangerous instructions
		for (const auto& pending_dangerous_address: variants[0].pending_dangerous_addresses)
			handle_dangerous_instruction(pending_dangerous_address.first, pending_dangerous_address.second, (ARG3(0) & PROT_EXEC) ? false : true);
		variants[0].pending_dangerous_addresses.clear();
#endif
	}
	return 0;
}

/*-----------------------------------------------------------------------------
  sys_pkey_alloc - (unsigned int flags, unsigned int access_rights)
-----------------------------------------------------------------------------*/
PRECALL(pkey_alloc)
{
	// TODO some work here
	return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

/*-----------------------------------------------------------------------------
  sys_pkey_mprotect -  (void *addr, size_t len, int prot, int pkey)
-----------------------------------------------------------------------------*/
LOG_ARGS(pkey_mprotect)
{
	debugf("%s - SYS_PKEY_MPROTECT(0x" PTRSTR ", %zd, " PTRSTR " = %s, %u)\n",
		   call_get_variant_pidstr().c_str(),
		   (unsigned long)ARG1(0),
		   (size_t)ARG2(0),
		   (unsigned long)ARG3(0),
		   getTextualProtectionFlags(ARG3(0)).c_str(),
		   (unsigned int)ARG4(0));
}

PRECALL(pkey_mprotect)
{
	// TODO some work here
	return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

CALL(pkey_mprotect)
{
#ifdef ENABLE_ERIM_POLICY
	if (pkey_mprotect_count < 2) {
		pkey_mprotect_count++;
		isolated_regions.push_back(std::make_pair((unsigned long)ARG1(0), (unsigned long)ARG2(0)));
	}
	else {
		warnf("Attempt to bypass ERIM_POLICY\n");
		return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
	}
#endif

#ifdef ENABLE_XOM_SWITCH_POLICY
	warnf("Attempt to bypass ENABLE_XOM_SWITCH_POLICY\n");
		return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
#endif

	return MVEE_CALL_ALLOW;
}

/*-----------------------------------------------------------------------------
  sys_chmod -

  man(2): (const char* filename, mode_t mode)
  kernel: (const char* filename, umode_t mode)
-----------------------------------------------------------------------------*/
LOG_ARGS(chmod)
{
	auto str1 = rw::read_string(variants[0].variantpid, (void*)ARG1(0));
	auto mode = getTextualFileMode(ARG2(0));

	debugf("%s - SYS_CHMOD(%s, 0x%08x = %s)\n",
		   call_get_variant_pidstr().c_str(),
		   str1.c_str(),
		   (unsigned int)ARG2(0),
		   mode.c_str());
}

CALL(chmod)
{
#ifdef MVEE_CERBERUS_CP_PKU_SANDBOX_ENABLED
	MutexLock lock(&mvee::special_lock);
	std::string full_path = get_full_path(AT_FDCWD, (void*)ARG1(0));
	struct stat sb{};
	if (stat(full_path.c_str(), &sb) == 0) {
		if (mvee::special_files.find(sb.st_ino) != mvee::special_files.end()) {
			warnf("Trying to change permissions of special file\n");
			return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
		}
	}
#endif

	return MVEE_CALL_ALLOW;
}

/*-----------------------------------------------------------------------------
  sys_fchmod -

  man(2): (int fd, mode_t mode)
  kernel: (unsigned int fd, umode_t mode)
-----------------------------------------------------------------------------*/
LOG_ARGS(fchmod)
{
	debugf("%s - SYS_FCHMOD(%u, %s)\n",
		   call_get_variant_pidstr().c_str(),
		   (unsigned int)ARG1(0),
		   getTextualFileMode(ARG2(0)).c_str());
}

CALL(fchmod)
{
#ifdef MVEE_CERBERUS_CP_PKU_SANDBOX_ENABLED
	MutexLock lock(&mvee::special_lock);
	std::string full_path = get_path_from_fd(ARG1(0));
	struct stat sb{};
	if (stat(full_path.c_str(), &sb) == 0) {
		if (mvee::special_files.find(sb.st_ino) != mvee::special_files.end()) {
			warnf("Trying to change permissions of special file\n");
			return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
		}
	}
#endif

	return MVEE_CALL_ALLOW;
}

/*-----------------------------------------------------------------------------
  sys_fchmodat -

  man(2): (int dirfd, const char *pathname, mode_t mode, int flags)
  kernel: (unsigned int fd, umode_t mode)
-----------------------------------------------------------------------------*/
LOG_ARGS(fchmodat)
{
	auto filename = rw::read_string(variants[0].variantpid, (void*)ARG2(0));

	debugf("%s - SYS_FCHMODAT(%d, %s, 0x%08X (%s), 0x%08X (%s))\n",
		   call_get_variant_pidstr().c_str(),
		   (int)ARG1(0),
		   filename.c_str(),
		   (int)ARG3(0), getTextualFileFlags(ARG3(0)).c_str(),
		   (int)ARG4(0), getTextualFileMode(ARG4(0) & S_FILEMODEMASK).c_str());
}

CALL(fchmodat)
{
#ifdef MVEE_CERBERUS_CP_PKU_SANDBOX_ENABLED
	MutexLock lock(&mvee::special_lock);
	std::string full_path = get_full_path(ARG1(0), (void*)ARG2(0));
	struct stat sb{};
	if (stat(full_path.c_str(), &sb) == 0) {
		if (mvee::special_files.find(sb.st_ino) != mvee::special_files.end()) {
			warnf("Trying to change permissions of special file\n");
			return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
		}
	}
#endif

	return MVEE_CALL_ALLOW;
}

/*-----------------------------------------------------------------------------
  sys_ioctl -

  man(2): (int fd, int cmd, ...)
  kernel: (unsigned int fd, unsigned int cmd, unsigned long arg)
-----------------------------------------------------------------------------*/
LOG_ARGS(ioctl)
{
	debugf("%s - SYS_IOCTL(%u, %u, 0x" PTRSTR ")\n",
		   call_get_variant_pidstr().c_str(),
		   (unsigned int)ARG1(0),
		   (unsigned int)ARG2(0),
		   (unsigned long)ARG3(0));
}

CALL(ioctl)
{
#ifdef MVEE_CERBERUS_CP_PKU_SANDBOX_ENABLED
	MutexLock lock(&mvee::special_lock);
	std::string full_path = get_path_from_fd(ARG1(0));
	struct stat sb{};
	if (stat(full_path.c_str(), &sb) == 0) {
		if (mvee::special_files.find(sb.st_ino) != mvee::special_files.end()) {
			warnf("Trying to change permissions of special file\n");
			return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
		}
	}
#endif

	return MVEE_CALL_ALLOW;
}

/*-----------------------------------------------------------------------------
  sys_ptrace -

  man(2): (enum __ptrace_request request, pid_t pid, void* addr, void* data)
  kernel: (long request, long pid, unsigned long addr, unsigned long data)
-----------------------------------------------------------------------------*/
LOG_ARGS(ptrace)
{
	debugf("%s - SYS_PTRACE(%s, %ld, 0x" PTRSTR ", 0x" PTRSTR ")\n",
		   call_get_variant_pidstr().c_str(),
		   getTextualPtraceRequest(ARG1(0)),
		   (long)ARG2(0),
		   (unsigned long)ARG3(0),
		   (unsigned long)ARG4(0));
}

CALL(ptrace)
{
	return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
}

/*-----------------------------------------------------------------------------
  sys_prctl - (int option, unsigned long arg2, unsigned long arg3,
  unsigned long arg4, unsigned long arg5)
-----------------------------------------------------------------------------*/
LOG_ARGS(prctl)
{
	debugf("%s - SYS_PRCTL(%d, %lu, %lu, %lu, %lu)\n",
		   call_get_variant_pidstr().c_str(),
		   (int)ARG1(0),
		   (unsigned long)ARG2(0),
		   (unsigned long)ARG3(0),
		   (unsigned long)ARG4(0),
		   (unsigned long)ARG5(0));
}

CALL(prctl)
{
#ifdef MVEE_CERBERUS_CP_PKU_SANDBOX_ENABLED
	if (ARG1(0) == PR_SET_SECCOMP)
		return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
#endif
	return MVEE_CALL_ALLOW;
}

/*-----------------------------------------------------------------------------
  sys_seccomp -

  man(2): (unsigned int op, unsigned int flags, void* uargs)
  kernel: (unsigned int op, unsigned int flags, const char* uargs)
-----------------------------------------------------------------------------*/
CALL(seccomp)
{
#ifdef MVEE_CERBERUS_CP_PKU_SANDBOX_ENABLED
	return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
#endif
	return MVEE_CALL_ALLOW;
}

/*-----------------------------------------------------------------------------
  sys_shmget - (key_t key, size_t size, int shmflg)
-----------------------------------------------------------------------------*/
CALL(shmget)
{
#ifdef MVEE_CERBERUS_CP_PKU_SANDBOX_ENABLED
	warnf("shmget is not supported yet\n");
	return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
#endif
	return MVEE_CALL_ALLOW;
}

/*-----------------------------------------------------------------------------
  sys_shmat - (int shmid, char * shmaddr, int shmflg)
-----------------------------------------------------------------------------*/
CALL(shmat)
{
#ifdef MVEE_CERBERUS_CP_PKU_SANDBOX_ENABLED
	warnf("shmat is not supported yet\n");
	return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
#endif
	return MVEE_CALL_ALLOW;
}

/*-----------------------------------------------------------------------------
    sys_shmdt -
    man(2): (const void *shmaddr)
-----------------------------------------------------------------------------*/
CALL(shmdt)
{
#ifdef MVEE_CERBERUS_CP_PKU_SANDBOX_ENABLED
	warnf("shmdt is not supported yet\n");
	return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
#endif
	return MVEE_CALL_ALLOW;
}

/*-----------------------------------------------------------------------------
  modify_ldt -
-----------------------------------------------------------------------------*/
CALL(modify_ldt)
{
#ifdef MVEE_CERBERUS_CP_PKU_SANDBOX_ENABLED
	return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
#endif
	return MVEE_CALL_ALLOW;
}

/*-----------------------------------------------------------------------------
  sys_rt_sigsuspend - (const sigset_t* sigset)
-----------------------------------------------------------------------------*/
LOG_ARGS(rt_sigsuspend)
{
	debugf("%s - SYS_RT_SIGSUSPEND(%s)\n",
		   call_get_variant_pidstr().c_str(),
		   getTextualSigSet(call_get_sigset((void*)ARG1(0), OLDCALLIFNOT(__NR_rt_sigsuspend))).c_str());
}

CALL(rt_sigsuspend)
{
	memcpy(&old_blocked_signals[0], &blocked_signals[0], sizeof(sigset_t));
	sigemptyset(&blocked_signals[0]);

	if (ARG1(0)) {
		sigset_t _set = call_get_sigset((void*)ARG1(0), OLDCALLIFNOT(__NR_rt_sigsuspend));

		for (int i = SIGINT; i < __SIGRTMAX; ++i)
			if (sigismember(&_set, i))
				sigaddset(&blocked_signals[0], i);
	}

	debugf("> SIGSUSPEND ENTRY - blocked signals are now: %s\n", getTextualSigSet(blocked_signals[0]).c_str());

	return MVEE_CALL_ALLOW;
}

POSTCALL(rt_sigsuspend)
{
	memcpy(&blocked_signals[0], &old_blocked_signals[0], sizeof(sigset_t));
	sigemptyset(&old_blocked_signals[0]);

	debugf("> SIGSUSPEND EXIT - blocked signals are now: %s\n", getTextualSigSet(blocked_signals[0]).c_str());

	return MVEE_POSTCALL_HANDLED_UNSYNCED_CALL;
}

/*-----------------------------------------------------------------------------
  sys_signal - (int sig, __sighandler_t handler)
-----------------------------------------------------------------------------*/
LOG_ARGS(signal)
{
	debugf("%s - SYS_SIGNAL(%s, 0x" PTRSTR ")\n",
		   call_get_variant_pidstr().c_str(),
		   getTextualSig(ARG1(0)),
		   (unsigned long)ARG2(0));
}

CALL(signal)
{
	// prohibit call if the variant set is shutting down
	if (set_mmap_table->thread_group_shutting_down)
		return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EINVAL);
	return MVEE_CALL_ALLOW;
}

POSTCALL(signal)
{
	if (call_succeeded) {
		struct sigaction action{};
		memset(&action, 0, sizeof(struct sigaction));
		action.sa_handler = (__sighandler_t)ARG2(0);
		action.sa_flags   = SA_ONESHOT | SA_NOMASK;
		sigemptyset(&action.sa_mask);
		set_sighand_table->set_sigaction(ARG1(0), &action);
	}

	return 0;
}

/*-----------------------------------------------------------------------------
  sys_rt_sigaction - (int sig, const struct sigaction* act, struct sigaction*
  oact, size_t sigsetsize)
-----------------------------------------------------------------------------*/
LOG_ARGS(rt_sigaction)
{
	struct sigaction DEBUGVAR action = call_get_sigaction((void*) ARG2(0), OLDCALLIFNOT(__NR_rt_sigaction));

	debugf("%s - SYS_RT_SIGACTION(%d - %s - %s)\n",
		   call_get_variant_pidstr().c_str(),
		   (int)ARG1(0),
		   getTextualSig(ARG1(0)),
		   (action.sa_handler == SIG_DFL) ? "SIG_DFL" :
		   (action.sa_handler == SIG_IGN) ? "SIG_IGN" :
		   (action.sa_handler == (__sighandler_t)-2) ? "---" : "SIG_PTR"
	);
}

CALL(rt_sigaction)
{
	// prohibit call if the variant set is shutting down
	if (set_mmap_table->thread_group_shutting_down)
		return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EINVAL);
	return MVEE_CALL_ALLOW;
}

POSTCALL(rt_sigaction)
{
	if (call_succeeded && ARG2(0)) {
		struct sigaction action = call_get_sigaction((void*) ARG2(0), OLDCALLIFNOT(__NR_rt_sigaction));
		set_sighand_table->set_sigaction(ARG1(0), &action);
	}

	return 0;
}

/*-----------------------------------------------------------------------------
  sys_sigreturn -

  man(2): (unsigned long unused)
  kernel: (void)
-----------------------------------------------------------------------------*/
LOG_ARGS(rt_sigreturn)
{
	debugf("%s - SYS_RT_SIGRETURN()\n", call_get_variant_pidstr().c_str());
}

CALL(rt_sigreturn)
{
	if (variants[0].callnumbackup == __NR_rt_sigsuspend) {
		// in this case sigreturn returns straight to sigsuspend and we don't see
		// a sigreturn return...
		// return_from_sighandler will change the callnum so that the next
		// syscall site will be the return of sigsuspend
		sig_return_from_sighandler();
	}

	return MVEE_CALL_ALLOW;
}

POSTCALL(rt_sigreturn)
{
	// if we did not deliver during sigsuspend, we will actually see sigreturn return -1
	// return_from_sighandler will restore the original context and resume
	sig_return_from_sighandler();
	return MVEE_POSTCALL_DONTRESUME;
}

/*-----------------------------------------------------------------------------
  sys_rt_sigprocmask - We use these handlers for sys_rt_sigprocmask AND
  sys_sigprocmask.  The two calls are very similar. They differ in two respects:

  * sys_sigprocmask accepts 'old_sigset_t' (aka 'unsigned int') arguments.
  sys_rt_sigprocmask accepts 'sigset_t' (aka 'unsigned long') arguments.

  * sys_rt_sigprocmask accepts a sigsetsize argument. sys_sigprocmask does not.

  There is no rt_sigprocmask wrapper in user space. sigprocmask just calls one
  of the two syscalls, depending on which platform you're on.

  Args for the syscalls:

  * sys_rt_sigprocmask: (int how, sigset_t* nset, sigset_t* oset, size_t
  sigsetsize)

  * sys_sigprocmask: (int how, sigset_t* nset, sigset_t* oset)
-----------------------------------------------------------------------------*/
LOG_ARGS(rt_sigprocmask)
{
	debugf("%s - SYS_RT_SIGPROCMASK(%s, 0x" PTRSTR " - %s)\n",
		   call_get_variant_pidstr().c_str(),
		   getTextualSigHow(ARG1(0)), (unsigned long)ARG2(0),
		   getTextualSigSet(call_get_sigset((void*) ARG2(0), OLDCALLIFNOT(__NR_rt_sigprocmask))).c_str());
}

CALL(rt_sigprocmask)
{
	variants[0].last_sigset = call_get_sigset((void*) ARG2(0), OLDCALLIFNOT(__NR_rt_sigprocmask));
	return MVEE_CALL_ALLOW;
}

POSTCALL(rt_sigprocmask)
{
	if (call_succeeded && ARG2(0)) {
		sigset_t _set = variants[0].last_sigset;

		switch (ARG1(0)) {
			case SIG_BLOCK:
			{
				for (int i = 1; i < SIGRTMAX + 1; ++i)
					if (sigismember(&_set, i))
						sigaddset(&blocked_signals[0], i);
				break;
			}
			case SIG_UNBLOCK:
			{
				for (int i = 1; i < SIGRTMAX + 1; ++i)
					if (sigismember(&_set, i))
						sigdelset(&blocked_signals[0], i);
				break;
			}
			case SIG_SETMASK:
			{
				sigemptyset(&blocked_signals[0]);
				for (int i = 1; i < SIGRTMAX + 1; ++i)
					if (sigismember(&_set, i))
						sigaddset(&blocked_signals[0], i);
				break;
			}
		}
	}

	return MVEE_POSTCALL_HANDLED_UNSYNCED_CALL;
}

/*-----------------------------------------------------------------------------
  sys_pselect6 - like select but:

  - the fifth argument is a struct timespec ptr, not a struct timeval ptr
  - the timespec is constant for pselect. select may modify the timeval
  - pselect sets a sigmask while inside the call. select does not have this arg


  (int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds,
  const struct timespec* timeout, const sigset_t* sigmask)
-----------------------------------------------------------------------------*/
LOG_ARGS(pselect6)
{
	struct timespec timeout{};
	std::stringstream timestr;

	if (ARG5(0)) {
		if (!rw::read_struct(variants[0].variantpid, (void*) ARG5(0), sizeof(struct timespec), &timeout))
			throw RwMemFailure(0, "read timeout in sys_pselect6");

		timestr << "TIMEOUT: " << timeout.tv_sec << std::setw(9) << std::setfill('0') << timeout.tv_nsec << std::setw(0) << " s";
	}
	else {
		timestr << "TIMEOUT: none";
	}

	debugf("%s - SYS_PSELECT6(%d, 0x" PTRSTR ", 0x" PTRSTR ", 0x" PTRSTR ", %s, %s)\n",
		   call_get_variant_pidstr().c_str(),
		   (int)ARG1(0),
		   (unsigned long)ARG2(0),
		   (unsigned long)ARG3(0),
		   (unsigned long)ARG4(0),
		   timestr.str().c_str(),
		   getTextualSigSet(call_get_sigset((void*) ARG6(0), true)).c_str());
}

PRECALL(pselect6)
{
	variants[0].last_sigset = blocked_signals[0];
	auto _set = call_get_sigset((void*) ARG6(0), true);
	sigemptyset(&blocked_signals[0]);
	for (int i = 1; i < SIGRTMAX+1; ++i)
		if (sigismember(&_set, i))
			sigaddset(&blocked_signals[0], i);

	return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

POSTCALL(pselect6)
{
	blocked_signals[0] = variants[0].last_sigset;
	return 0;
}

/*-----------------------------------------------------------------------------
  sys_msync -

  man(2): (void* start, size_t len, int flags)
  kernel: (unsigned long start, size_t len, int flags)
-----------------------------------------------------------------------------*/
LOG_ARGS(msync)
{
	debugf("%s - SYS_MSYNC(0x" PTRSTR ", %ld, %s)\n",
		   call_get_variant_pidstr().c_str(),
		   (unsigned long)ARG1(0),
		   (long)ARG2(0),
		   getTextualMSyncFlags(ARG3(0)).c_str());
}

CALL(msync)
{
#ifdef MVEE_CERBERUS_CP_PKU_SANDBOX_ENABLED
	warnf("msync is not supported yet\n");
	return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
#endif
	return MVEE_CALL_ALLOW;
}

/*-----------------------------------------------------------------------------
  sys_unshare -

  man(2): (int flags)
  kernel: (unsigned long flags)

  reverses the effect of sharing certain kernel data structures through
  sys_clone
-----------------------------------------------------------------------------*/
LOG_ARGS(unshare)
{
	debugf("%s - SYS_UNSHARE(%d)\n",
		   call_get_variant_pidstr().c_str(),
		   (int)ARG1(0));
}

CALL(unshare)
{
	//
	// This may be downright impossible to do in the general case as we do not
	// have a stop-the-world primitive in the MVEE.  There are two cases that we
	// COULD handle right now:
	//
	// 1) Unshare is called with arg 0. This is a no-op
	// 2) Unshare is called by a single-threaded process. In this case, we leave
	// the tables of the parent process intact, and we create new copies of
	// whatever tables are being unshared by this process
	//

	if (ARG1(0) == 0) {
		// this is a no-op... fine
		return MVEE_CALL_ALLOW;
	}
	else if (!is_program_multithreaded()) {
		// We can handle this...
		warnf("Unshare called by singlethreaded process. This is not implemented yet!\n");
		return MVEE_CALL_ALLOW;
	}
	else {
		// Program is multithreaded and tables are being unshared.
		// No way to handle this right now
		warnf("Unshare called by multithreaded process. This is not implemented yet!\n");
		return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
	}
}

/*-----------------------------------------------------------------------------
  sys_exit_group - (int error_code)

  NOTE: this syscall does not seem to complete until all variants have exited
-----------------------------------------------------------------------------*/
LOG_ARGS(exit_group)
{
	debugf("%s - SYS_EXIT_GROUP(%d)\n", 
		   call_get_variant_pidstr().c_str(),
		   (int)ARG1(0));
}

PRECALL(exit_group)
{
#ifdef MVEE_CERBERUS_CP_PKU_SANDBOX_ENABLED
	// if one of the variants tries to execute a dangerous XRSTOR from libc or ld
	// we end up here and we want to stop execution of all variants
	if (ARG1(0) == 666) {
		warnf("You Shall Not byPass my PKU-based Sandbox: Attempt to Execute a Dangerous Instruction\n");
		shutdown(false);
	}
#endif

	return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

CALL(exit_group)
{
	// don't let the exit_group call go through while we have "dangling variants"
	await_pending_transfers();

	// I needed this for raytrace and some other parsecs. They do a sys_exit_group
	// while a bunch of threads are still running.
	// This can cause mismatches in those other threads because some variants might still perform syscalls while the others are dead
	// warnf("thread group shutting down\n");

	set_mmap_table->thread_group_shutting_down = true;
	return MVEE_CALL_ALLOW;
}

/*-----------------------------------------------------------------------------
  handlers_setalias
-----------------------------------------------------------------------------*/
static void mvee_handlers_setalias(int callnum, int alias)
{
	auto it = mvee::syslocks_table.find(callnum);
	if (it != mvee::syslocks_table.end())
		mvee::syslocks_table.insert(std::pair<unsigned long, unsigned char>(alias, it->second));
}

/*-----------------------------------------------------------------------------
  init_syslocks -
-----------------------------------------------------------------------------*/
void mvee::init_syslocks()
{
    /*
    These annotations get picked up by the generate_syscall_table.rb script
    ALIAS rt_sigaction sigaction
    ALIAS rt_sigreturn sigreturn
    ALIAS rt_sigsuspend sigsuspend
    ALIAS rt_sigprocmask sigprocmask
    */

    // Syslock init
#define REG_LOCKS(callnum, locks) \
    mvee::syslocks_table.insert(std::pair<unsigned long, unsigned char>(callnum, locks))

    REG_LOCKS(MVEE_INVOKE_LD,           MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_FULL);

    // syscalls that create a new process or load a new process image
    REG_LOCKS(__NR_fork,                MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_execve,              MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_clone,               MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_FULL);

    // Special case that affects all tables
    REG_LOCKS(__NR_unshare,             MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_FULL);

    // normal syscalls that create/destroy/modify file descriptors
    // REG_LOCKS(__NR_open,                MVEE_SYSLOCK_FULL); // There seem to be blocking open calls in FF
    // REG_LOCKS(__NR_openat,              MVEE_SYSLOCK_FULL);
    // REG_LOCKS(__NR_dup,                 MVEE_SYSLOCK_FULL);
    // REG_LOCKS(__NR_dup2,                MVEE_SYSLOCK_FULL);
    // REG_LOCKS(__NR_dup3,                MVEE_SYSLOCK_FULL);
    // REG_LOCKS(__NR_pipe,                MVEE_SYSLOCK_FULL);
    // REG_LOCKS(__NR_pipe2,               MVEE_SYSLOCK_FULL);
    // REG_LOCKS(__NR_close,               MVEE_SYSLOCK_FULL);
    // REG_LOCKS(__NR_inotify_init,        MVEE_SYSLOCK_FULL);
    // REG_LOCKS(__NR_inotify_init1,       MVEE_SYSLOCK_FULL);
    // REG_LOCKS(__NR_fcntl,               MVEE_SYSLOCK_FULL);
    // REG_LOCKS(__NR_socket,              MVEE_SYSLOCK_FULL);
    // REG_LOCKS(__NR_socketpair,          MVEE_SYSLOCK_FULL);
    // REG_LOCKS(__NR_epoll_create,        MVEE_SYSLOCK_FULL);
    // REG_LOCKS(__NR_epoll_create1,       MVEE_SYSLOCK_FULL);
    // REG_LOCKS(__NR_epoll_ctl,           MVEE_SYSLOCK_FULL);

    // normal syscalls that read the file system
    // REG_LOCKS(__NR_chdir,               MVEE_SYSLOCK_POSTCALL);
    // REG_LOCKS(__NR_fchdir,              MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_POSTCALL);

    // master calls that create/destroy/modify file descriptors
    // REG_LOCKS(__NR_bind,                MVEE_SYSLOCK_FULL);
    // REG_LOCKS(__NR_select,              MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_POSTCALL); // may block
    // REG_LOCKS(__NR_accept,              MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_POSTCALL); // may block
    // REG_LOCKS(__NR_accept4,             MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_POSTCALL); // may block
    // REG_LOCKS(__NR_connect,             MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_POSTCALL); // may block
    REG_LOCKS(__NR_pselect6,            MVEE_SYSLOCK_SIG | MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_POSTCALL); // may block

    // syscalls with fd arguments
    // REG_LOCKS(__NR_fstat,       MVEE_SYSLOCK_PRECALL);
    // REG_LOCKS(__NR_fstatfs,     MVEE_SYSLOCK_PRECALL);
    // REG_LOCKS(__NR_getdents,    MVEE_SYSLOCK_PRECALL);
    // REG_LOCKS(__NR_getdents64,  MVEE_SYSLOCK_PRECALL);
    // REG_LOCKS(__NR_read,        MVEE_SYSLOCK_PRECALL);
    // REG_LOCKS(__NR_readv,       MVEE_SYSLOCK_PRECALL);
    // REG_LOCKS(__NR_pread64,     MVEE_SYSLOCK_PRECALL);
    // REG_LOCKS(__NR_preadv,      MVEE_SYSLOCK_PRECALL);
    // REG_LOCKS(__NR_write,       MVEE_SYSLOCK_PRECALL);
    // REG_LOCKS(__NR_writev,      MVEE_SYSLOCK_PRECALL);
    // REG_LOCKS(__NR_pwrite64,    MVEE_SYSLOCK_PRECALL);
    // REG_LOCKS(__NR_pwritev,     MVEE_SYSLOCK_PRECALL);
    // REG_LOCKS(__NR_linkat,      MVEE_SYSLOCK_PRECALL);
    // REG_LOCKS(__NR_unlinkat,    MVEE_SYSLOCK_PRECALL);
    // REG_LOCKS(__NR_lseek,       MVEE_SYSLOCK_PRECALL);
    // REG_LOCKS(__NR_fsync,       MVEE_SYSLOCK_PRECALL);
    // REG_LOCKS(__NR_ioctl,       MVEE_SYSLOCK_PRECALL);
    // REG_LOCKS(__NR_symlinkat,   MVEE_SYSLOCK_PRECALL);
    // REG_LOCKS(__NR_listen,      MVEE_SYSLOCK_PRECALL);
    // REG_LOCKS(__NR_getsockname, MVEE_SYSLOCK_PRECALL);
    // REG_LOCKS(__NR_getsockopt,  MVEE_SYSLOCK_PRECALL);
    // REG_LOCKS(__NR_getpeername, MVEE_SYSLOCK_PRECALL);
    // REG_LOCKS(__NR_setsockopt,  MVEE_SYSLOCK_PRECALL);
    // REG_LOCKS(__NR_sendto,      MVEE_SYSLOCK_PRECALL);
    // REG_LOCKS(__NR_sendmmsg,    MVEE_SYSLOCK_PRECALL);
    // REG_LOCKS(__NR_sendmsg,     MVEE_SYSLOCK_PRECALL);
    // REG_LOCKS(__NR_recvfrom,    MVEE_SYSLOCK_PRECALL);
    // REG_LOCKS(__NR_recvmmsg,    MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_POSTCALL);
    // REG_LOCKS(__NR_recvmsg,     MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_POSTCALL);
    // REG_LOCKS(__NR_shutdown,    MVEE_SYSLOCK_PRECALL);
    // REG_LOCKS(__NR_fdatasync,   MVEE_SYSLOCK_PRECALL);
    // REG_LOCKS(__NR_poll,        MVEE_SYSLOCK_PRECALL);
    // REG_LOCKS(__NR_sendfile,    MVEE_SYSLOCK_PRECALL);

    // normal syscalls with mman creations/deletions/modifications
    REG_LOCKS(__NR_msync,       MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_mmap,        MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_mremap,      MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_FULL);
    // REG_LOCKS(__NR_brk,         MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_mprotect,    MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_munmap,      MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_prctl,       MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_exit_group,  MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_PRECALL);
    REG_LOCKS(__NR_exit,        MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_PRECALL);

    // non-blocking syscalls that read/modify the sighand table
    REG_LOCKS(__NR_rt_sigaction,   MVEE_SYSLOCK_SIG | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_rt_sigprocmask, MVEE_SYSLOCK_SIG | MVEE_SYSLOCK_FULL);

    // blocking syscalls that read/modify the sighand table
    REG_LOCKS(__NR_rt_sigsuspend,  MVEE_SYSLOCK_SIG | MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_POSTCALL);

    // syscalls that read the process name
    // REG_LOCKS(__NR_setsid, MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_PRECALL);

    // IPC calls
    REG_LOCKS(__NR_shmat, MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_FULL);

#include "MVEE_syscall_alias_locks.h"
}
