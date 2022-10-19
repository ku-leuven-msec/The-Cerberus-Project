/*
 * Cerberus PKU-based Sandbox
 *
 * Check Cerberus/cerberus_ReMon/README.md for licensing terms.
 */

#include <sys/ptrace.h>
#include <sys/un.h>
#include <sched.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <sys/random.h>
#include <linux/mman.h>
#include "MVEE.h"
#include "MVEE_monitor.h"
#include "MVEE_logging.h"
#include "MVEE_syscall_string_table.h"
#include "MVEE_signals.h"
#include "MVEE_fake_syscall.h"
#include "MVEE_interaction.h"

/*-----------------------------------------------------------------------------
    Flag Check Macro
-----------------------------------------------------------------------------*/
#define TEST_FLAG(flags, flag, str)                                         \
	if ((flags & flag) || (flags == flag) || ((flag == 0) && !(flags & 1))) \
	{                                                                       \
		if (!str.empty())                                                   \
			str += " | ";                                                   \
		str += #flag;                                                       \
	}

#define DEF_CASE(a) \
	case a:         \
	result = #a;    \
	break;

/*-----------------------------------------------------------------------------
    getTextualState
-----------------------------------------------------------------------------*/
const char* getTextualState(unsigned int state)
{
	const char* result = "UNKNOWN";

	switch(state) {
		DEF_CASE(STATE_WAITING_ATTACH);
		DEF_CASE(STATE_WAITING_RESUME);
		DEF_CASE(STATE_NORMAL);
		DEF_CASE(STATE_IN_SYSCALL);
		DEF_CASE(STATE_IN_FORKCALL);
	}

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualSig
-----------------------------------------------------------------------------*/
const char* getTextualSig(unsigned int sig)
{
	const char* result = "UNKNOWN";

	switch(sig) {
		DEF_CASE(SIGALRM)
		DEF_CASE(SIGHUP)
		DEF_CASE(SIGINT)
		DEF_CASE(SIGKILL)
		DEF_CASE(SIGPIPE)
		DEF_CASE(SIGPOLL)
		DEF_CASE(SIGPROF)
		DEF_CASE(SIGTERM)
		DEF_CASE(SIGUSR1)
		DEF_CASE(SIGUSR2)
		DEF_CASE(SIGVTALRM)
		// DEF_CASE(STKFLT) - Undefined on linux
		DEF_CASE(SIGPWR)
		DEF_CASE(SIGWINCH)
		DEF_CASE(SIGCHLD)
		DEF_CASE(SIGURG)
		DEF_CASE(SIGTSTP)
		DEF_CASE(SIGTTIN)
		DEF_CASE(SIGTTOU)
		DEF_CASE(SIGSTOP)
		DEF_CASE(SIGCONT)
		DEF_CASE(SIGABRT)
		DEF_CASE(SIGFPE)
		DEF_CASE(SIGILL)
		DEF_CASE(SIGQUIT)
		DEF_CASE(SIGSEGV)
#if SIGTRAP != SIGSYSTRAP
		DEF_CASE(SIGSYSTRAP)
#endif
		DEF_CASE(SIGTRAP)
		DEF_CASE(SIGSYS)
		// DEF_CASE(SIGEMT) - Undefined on linux
		DEF_CASE(SIGBUS)
		DEF_CASE(SIGXCPU)
		DEF_CASE(SIGXFSZ)
		DEF_CASE(SIGCANCEL)
		DEF_CASE(SIGSETXID)
	}

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualSigHow
-----------------------------------------------------------------------------*/
const char* getTextualSigHow(int how)
{
	const char* result = "SIG_???";

	switch(how) {
		DEF_CASE(SIG_BLOCK);
		DEF_CASE(SIG_UNBLOCK);
		DEF_CASE(SIG_SETMASK);
	}

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualPtraceRequest
-----------------------------------------------------------------------------*/
const char* getTextualPtraceRequest(unsigned int request)
{
	const char* result = "PTRACE_UNKNOWN";

	switch(request) {
		DEF_CASE(PTRACE_TRACEME);
		DEF_CASE(PTRACE_PEEKTEXT);
		DEF_CASE(PTRACE_PEEKDATA);
		DEF_CASE(PTRACE_PEEKUSER);
		DEF_CASE(PTRACE_POKETEXT);
		DEF_CASE(PTRACE_POKEDATA);
		DEF_CASE(PTRACE_POKEUSER);
		DEF_CASE(PTRACE_CONT);
		DEF_CASE(PTRACE_KILL);
		DEF_CASE(PTRACE_SINGLESTEP);
		DEF_CASE(PTRACE_ATTACH);
		DEF_CASE(PTRACE_DETACH);
		DEF_CASE(PTRACE_SYSCALL);
		DEF_CASE(PTRACE_SETOPTIONS);
		DEF_CASE(PTRACE_GETREGS);
		DEF_CASE(PTRACE_SETREGS);
		DEF_CASE(PTRACE_GETEVENTMSG);
		DEF_CASE(PTRACE_GETSIGINFO);
		DEF_CASE(PTRACE_SETSIGINFO);
		DEF_CASE(PROCESS_VM_READV);
		DEF_CASE(PROCESS_VM_WRITEV);
	}

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualSyscall
-----------------------------------------------------------------------------*/
const char* getTextualSyscall(long int syscallnum)
{
	const char* result = "sys_unknown";

	if (syscallnum < 0)
		result = "EXIT";
	else if (syscallnum < MAX_CALLS) {
		result = mvee_syscall_string_table[syscallnum];
	}
	else {
		// fake syscall numbers defined by monitor
		switch(syscallnum) {
			DEF_CASE(NO_CALL);
			DEF_CASE(MVEE_RDTSC_FAKE_SYSCALL);
			DEF_CASE(MVEE_RUNS_UNDER_MVEE_CONTROL);
			DEF_CASE(MVEE_INVOKE_LD);
			DEF_CASE(MVEE_JUMPS_SETUP);
			DEF_CASE(MVEE_GET_SENSITIVE_INODE);
			DEF_CASE(MVEE_SPECIAL_PAGE_SETUP);
		}
	}

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualSEGVCode
-----------------------------------------------------------------------------*/
const char* getTextualSEGVCode(int code)
{
	const char* result = "(unknown)";

	switch(code) {
		DEF_CASE(SI_USER);
		DEF_CASE(SI_KERNEL);
		DEF_CASE(SI_QUEUE);
		DEF_CASE(SI_TIMER);
		DEF_CASE(SI_MESGQ);
		DEF_CASE(SI_ASYNCIO);
		DEF_CASE(SI_SIGIO);
		DEF_CASE(SI_TKILL);
		DEF_CASE(SEGV_MAPERR);
		DEF_CASE(SEGV_ACCERR);
	}

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualKernelError
-----------------------------------------------------------------------------*/
const char* getTextualKernelError(int err)
{
	const char* result = "(unknown)";

	switch(err) {
		DEF_CASE(ERESTARTSYS);
		DEF_CASE(ERESTARTNOINTR);
		DEF_CASE(ERESTARTNOHAND);
		DEF_CASE(ENOIOCTLCMD);
		DEF_CASE(ERESTART_RESTARTBLOCK);
		DEF_CASE(EBADHANDLE);
		DEF_CASE(ENOTSYNC);
		DEF_CASE(EBADCOOKIE);
		DEF_CASE(ENOTSUPP);
		DEF_CASE(ETOOSMALL);
		DEF_CASE(ESERVERFAULT);
		DEF_CASE(EBADTYPE);
		DEF_CASE(EJUKEBOX);
		DEF_CASE(EIOCBQUEUED);
		DEF_CASE(EIOCBRETRY);
	}

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualBreakpointType
-----------------------------------------------------------------------------*/
const char* getTextualBreakpointType(int bp_type)
{
	const char* result = "(unknown)";

	switch(bp_type) {
		DEF_CASE(MVEE_BP_EXEC_ONLY);
		DEF_CASE(MVEE_BP_WRITE_ONLY);
		DEF_CASE(MVEE_BP_READ_WRITE);
		DEF_CASE(MVEE_BP_READ_WRITE_NO_FETCH);
		DEF_CASE(MVEE_BP_EXEC_ONLY_XRSTOR);
	}

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualErrno
-----------------------------------------------------------------------------*/
const char* getTextualErrno(int err)
{
	const char* result = "Unknown Error";

	switch (err) {
		default:
			result = strerror(err);
			break;
	}

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualMremapFlags
-----------------------------------------------------------------------------*/
const char* getTextualMremapFlags(int flags)
{
	const char* result = "<none>";

	switch (flags) {
		DEF_CASE(MREMAP_MAYMOVE);
		DEF_CASE(MREMAP_FIXED);
	}

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualFileFlags
-----------------------------------------------------------------------------*/
std::string getTextualFileFlags(int flags)
{
	std::string result;

	TEST_FLAG(flags, O_RDONLY,    result);
	TEST_FLAG(flags, O_WRONLY,    result);
	TEST_FLAG(flags, O_RDWR,      result);
	TEST_FLAG(flags, O_APPEND,    result);
	TEST_FLAG(flags, O_ASYNC,     result);
	TEST_FLAG(flags, O_CREAT,     result);
	TEST_FLAG(flags, O_DIRECT,    result);
	TEST_FLAG(flags, O_DIRECTORY, result);
	TEST_FLAG(flags, O_EXCL,      result);
	TEST_FLAG(flags, O_LARGEFILE, result);
	TEST_FLAG(flags, O_NOATIME,   result);
	TEST_FLAG(flags, O_NOCTTY,    result);
	TEST_FLAG(flags, O_NOFOLLOW,  result);
	TEST_FLAG(flags, O_NONBLOCK,  result);
	TEST_FLAG(flags, O_SYNC,      result);
	TEST_FLAG(flags, O_TRUNC,     result);
	TEST_FLAG(flags, O_CLOEXEC,   result);

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualFileMode
-----------------------------------------------------------------------------*/
std::string getTextualFileMode(int mode)
{
	std::string result;

	// Permissions
	TEST_FLAG(mode, S_IRUSR,  result);
	TEST_FLAG(mode, S_IWUSR,  result);
	TEST_FLAG(mode, S_IXUSR,  result);
	TEST_FLAG(mode, S_IRGRP,  result);
	TEST_FLAG(mode, S_IWGRP,  result);
	TEST_FLAG(mode, S_IXGRP,  result);
	TEST_FLAG(mode, S_IROTH,  result);
	TEST_FLAG(mode, S_IWOTH,  result);
	TEST_FLAG(mode, S_IXOTH,  result);

	// File Types
	TEST_FLAG(mode, S_IFMT,   result);
	TEST_FLAG(mode, S_IFDIR,  result);
	TEST_FLAG(mode, S_IFCHR,  result);
	TEST_FLAG(mode, S_IFBLK,  result);
	TEST_FLAG(mode, S_IFREG,  result);
	TEST_FLAG(mode, S_IFIFO,  result);
	TEST_FLAG(mode, S_IFLNK,  result);
	TEST_FLAG(mode, S_IFSOCK, result);

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualProtectionFlags
-----------------------------------------------------------------------------*/
std::string getTextualProtectionFlags(int mode)
{
	std::string result;

	TEST_FLAG(mode, PROT_EXEC,      result);
	TEST_FLAG(mode, PROT_READ,      result);
	TEST_FLAG(mode, PROT_WRITE,     result);
	TEST_FLAG(mode, PROT_NONE,      result);
	TEST_FLAG(mode, PROT_GROWSDOWN, result);
	TEST_FLAG(mode, PROT_GROWSUP,   result);

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualCloneFlags
-----------------------------------------------------------------------------*/
std::string getTextualCloneFlags(unsigned int flags)
{
	std::string result;

	TEST_FLAG(flags, CLONE_CHILD_CLEARTID, result);
	TEST_FLAG(flags, CLONE_CHILD_SETTID,   result);
	TEST_FLAG(flags, CLONE_FILES,          result);
	TEST_FLAG(flags, CLONE_FS,             result);
	TEST_FLAG(flags, CLONE_IO,             result);
	TEST_FLAG(flags, CLONE_NEWIPC,         result);
	TEST_FLAG(flags, CLONE_NEWNET,         result);
	TEST_FLAG(flags, CLONE_NEWNS,          result);
	TEST_FLAG(flags, CLONE_NEWPID,         result);
	TEST_FLAG(flags, CLONE_NEWUTS,         result);
	TEST_FLAG(flags, CLONE_PARENT,         result);
	TEST_FLAG(flags, CLONE_PARENT_SETTID,  result);
	// TEST_FLAG(flags, CLONE_PID           , result);
	TEST_FLAG(flags, CLONE_PTRACE,         result);
	TEST_FLAG(flags, CLONE_SETTLS,         result);
	TEST_FLAG(flags, CLONE_SIGHAND,        result);
	// TEST_FLAG(flags, CLONE_STOPPED       , result);
	TEST_FLAG(flags, CLONE_SYSVSEM,        result);
	TEST_FLAG(flags, CLONE_THREAD,         result);
	TEST_FLAG(flags, CLONE_UNTRACED,       result);
	TEST_FLAG(flags, CLONE_VFORK,          result);
	TEST_FLAG(flags, CLONE_VM,             result);

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualMapType
-----------------------------------------------------------------------------*/
std::string getTextualMapType(int mode)
{
	std::string result;
	// MAP_SHARED_VALIDATE is not a multiple of 2 :(
	if ((mode & MAP_SHARED_VALIDATE) == MAP_SHARED_VALIDATE) {
		TEST_FLAG(mode, MAP_SHARED_VALIDATE, result);
	}
	else {
		TEST_FLAG(mode, MAP_SHARED, result);
		TEST_FLAG(mode, MAP_PRIVATE, result);
	}
	TEST_FLAG(mode, MAP_FIXED,           result);
	TEST_FLAG(mode, MAP_ANONYMOUS,       result);
	// TEST_FLAG(mode, MAP_32BIT,           result);
	TEST_FLAG(mode, MAP_GROWSDOWN,       result);
	TEST_FLAG(mode, MAP_DENYWRITE,       result);
	TEST_FLAG(mode, MAP_EXECUTABLE,      result);
	TEST_FLAG(mode, MAP_LOCKED,          result);
	TEST_FLAG(mode, MAP_NORESERVE,       result);
	TEST_FLAG(mode, MAP_POPULATE,        result);
	TEST_FLAG(mode, MAP_NONBLOCK,        result);
	TEST_FLAG(mode, MAP_STACK,           result);

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualSigset
-----------------------------------------------------------------------------*/
std::string getTextualSigSet(sigset_t set)
{
	std::string result;

	for (int i = 1; i < SIGRTMAX+1; ++i) {
		if (sigismember(&set, i)) {
			if (!result.empty())
				result += " | ";
			result += getTextualSig(i);
		}
	}

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualMSyncFlags -
-----------------------------------------------------------------------------*/
std::string getTextualMSyncFlags(int flags)
{
	std::string result;

	TEST_FLAG(flags, MS_ASYNC,      result);
	TEST_FLAG(flags, MS_SYNC,       result);
	TEST_FLAG(flags, MS_INVALIDATE, result);

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualSigactionFlags
-----------------------------------------------------------------------------*/
std::string getTextualSigactionFlags(unsigned int flags)
{
	std::string result;

	TEST_FLAG(flags, SA_NOCLDSTOP, result);
	TEST_FLAG(flags, SA_NOCLDWAIT, result);
	TEST_FLAG(flags, SA_NODEFER,   result);
	TEST_FLAG(flags, SA_ONSTACK,   result);
	TEST_FLAG(flags, SA_RESETHAND, result);
	TEST_FLAG(flags, SA_RESTART,   result);
	TEST_FLAG(flags, SA_SIGINFO,   result);

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualPerfFlags
-----------------------------------------------------------------------------*/
std::string getTextualPerfFlags(unsigned long flags)
{
	std::string result;

	TEST_FLAG(flags, PERF_FLAG_FD_CLOEXEC,  result);
	TEST_FLAG(flags, PERF_FLAG_FD_NO_GROUP, result);
	TEST_FLAG(flags, PERF_FLAG_FD_OUTPUT,   result);
	TEST_FLAG(flags, PERF_FLAG_PID_CGROUP,  result);

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualMVEEWaitStatus
-----------------------------------------------------------------------------*/
std::string getTextualMVEEWaitStatus(interaction::mvee_wait_status& status)
{
	std::stringstream ss;
	ss << "[PID: " << status.pid << ", reason: ";

	switch (status.reason) {
		case STOP_NOTSTOPPED: 
			ss << "STOP_NOTSTOPPED";
			break;
		case STOP_SYSCALL:
			ss << "STOP_SYSCALL";
			break;
		case STOP_SIGNAL:
			ss << "STOP_SIGNAL";
			break;
		case STOP_EXECVE:
			ss << "STOP_EXECVE";
			break;
		case STOP_FORK:
			ss << "STOP_FORK";
			break;
		case STOP_EXIT:
			ss << "STOP_EXIT";
			break;
		case STOP_KILLED:
			ss << "STOP_KILLED";
			break;
	}

	ss << ", sig: " << getTextualSig(status.data) << "]";
	return ss.str();
}
