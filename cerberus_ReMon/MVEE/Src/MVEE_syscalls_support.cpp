/*
 * Cerberus PKU-based Sandbox
 *
 * Check Cerberus/cerberus_ReMon/README.md for licensing terms.
 */

#include <sys/types.h>
#include <cstring>
#include <sstream>
#include <iomanip>
#include "MVEE.h"
#include "MVEE_monitor.h"
#include "MVEE_memory.h"
#include "MVEE_signals.h"
#include "MVEE_mman.h"
#include "MVEE_interaction.h"

/*-----------------------------------------------------------------------------
    call_check_regs
-----------------------------------------------------------------------------*/
void monitor::call_check_regs()
{
	if (!variants[0].regs_valid) {
		if (!interaction::read_all_regs(variants[0].variantpid, &variants[0].regs))
			throw RwRegsFailure(0, "refresh syscall args");
		variants[0].regs_valid = true;
	}
}

/*-----------------------------------------------------------------------------
    call_check_result - Checks the result value of a system call and
    returns false if the result value indicates an error.
-----------------------------------------------------------------------------*/
bool monitor::call_check_result(long int result)
{
	/*
	 * from unix/sysv/linux/sysdep.h:
	 * Linux uses a negative return value to indicate syscall errors,
	 * unlike most Unices, which use the condition codes' carry flag.
	 * Since version 2.1 the return value of a system call might be
	 * negative even if the call succeeded.  E.g., the `lseek' system call
	 * might return a large offset.  Therefore we must not anymore test
	 * for < 0, but test for a real error by making sure the value in %eax
	 * is a real error number.  Linus said he will make sure the no syscall
	 * returns a value in -1 .. -4095 as a valid result so we can savely
	 * test with -4095.
	 */
	return ((result > -1) || (result < -4095)) ? true : false;
}

/*-----------------------------------------------------------------------------
    call_postcall_get_variant_result
-----------------------------------------------------------------------------*/
long monitor::call_postcall_get_variant_result()
{
	if (!variants[0].return_valid) {
		unsigned long tmp;
		if (!interaction::fetch_syscall_return(variants[0].variantpid, tmp))
			throw RwRegsFailure(0, "read syscall result");
		variants[0].return_valid = true;
		variants[0].return_value = (long)tmp;
	}

	return variants[0].return_value;
}

/*-----------------------------------------------------------------------------
    call_postcall_set_variant_result
-----------------------------------------------------------------------------*/
void monitor::call_postcall_set_variant_result(unsigned long result)
{
	variants[0].return_valid = true;
	variants[0].return_value = result;
	if (!interaction::write_syscall_return(variants[0].variantpid, result))
		throw RwRegsFailure(0, "write syscall result");
}

/*-----------------------------------------------------------------------------
    call_get_sigset
-----------------------------------------------------------------------------*/
sigset_t monitor::call_get_sigset(void* sigset_ptr, bool is_old_call)
{
	sigset_t set;
	sigemptyset(&set);

	if (sigset_ptr) {
		if (is_old_call) {
			unsigned int __set;
			if (!rw::read_struct(variants[0].variantpid, sigset_ptr, sizeof(unsigned int), &__set))
				throw RwMemFailure(0, "read sigset (old)");
			set = mvee::old_sigset_to_new_sigset(__set);
		}
		else {
			if (!rw::read_struct(variants[0].variantpid, sigset_ptr, sizeof(sigset_t), &set))
				throw RwMemFailure(0, "read sigset (new)");
		}
	}

	return set;
}

/*-----------------------------------------------------------------------------
    call_overwrite_arg_value
-----------------------------------------------------------------------------*/
void monitor::call_overwrite_arg_value(int argnum, long new_value, bool needs_restore)
{
	long old_value;

	switch(argnum) {
#define SWAP(num)                       \
		case num:                       \
			old_value = ARG##num(0);    \
			SETARG##num(0, new_value);  \
			break;
		SWAP(1);
		SWAP(2);
		SWAP(3);
		SWAP(4);
		SWAP(5);
		SWAP(6);
		default:
			warnf("Tried to overwrite invalid syscall arg: %d\n", argnum);
			return;
	}

	if (needs_restore) {
		variants[0].have_overwritten_args = true;
		overwritten_syscall_arg arg;
		arg.syscall_arg_num = argnum;
		arg.arg_old_value = old_value;
		variants[0].overwritten_args.push_back(arg);
	}
}

/*-----------------------------------------------------------------------------
    call_restore_args
-----------------------------------------------------------------------------*/
void monitor::call_restore_args()
{
	variants[0].have_overwritten_args = false;

	for (const auto& arg : variants[0].overwritten_args) {
		switch(arg.syscall_arg_num) {
#define RESTOREVAL(num)                             \
			case num:                               \
				SETARG##num(0, arg.arg_old_value);  \
				break;
			RESTOREVAL(1);
			RESTOREVAL(2);
			RESTOREVAL(3);
			RESTOREVAL(4);
			RESTOREVAL(5);
			RESTOREVAL(6);
			default: break;
		}
	}

	variants[0].overwritten_args.clear();

	debugf("Restored syscall args in variant %d\n", 0);
}

/*-----------------------------------------------------------------------------
    call_get_sigaction
-----------------------------------------------------------------------------*/
struct sigaction monitor::call_get_sigaction(void* sigaction_ptr, bool is_old_call)
{
	struct sigaction result{};
	memset(&result, 0, sizeof(struct sigaction));

	if (sigaction_ptr) {
		if (is_old_call) {
			old_kernel_sigaction action{};

			if (!rw::read_struct(variants[0].variantpid, sigaction_ptr, sizeof(action), &action))
				throw RwMemFailure(0, "read sigaction (old)");

			result.sa_handler  = action.k_sa_handler;
			result.sa_restorer = action.sa_restorer;
			result.sa_flags    = action.sa_flags;
			result.sa_mask     = mvee::old_sigset_to_new_sigset(action.sa_mask);
		}
		else {
			struct kernel_sigaction action{};

			if (!rw::read_struct(variants[0].variantpid, sigaction_ptr, sizeof(action), &action))
				throw RwMemFailure(0, "read sigaction (new)");

			result.sa_handler  = action.k_sa_handler;
			result.sa_restorer = action.sa_restorer;
			result.sa_flags    = action.sa_flags;
			memcpy(&result.sa_mask, &action.sa_mask, sizeof(sigset_t));
		}
	}

	return result;
}

/*-----------------------------------------------------------------------------
    call_get_variant_pidstr
-----------------------------------------------------------------------------*/
std::string monitor::call_get_variant_pidstr()
{
	std::stringstream ss;
	ss << "Variant:" << 0
	   << " [PID:" << std::setw(5) << std::setfill('0') << variants[0].variantpid << std::setw(0) << "]";
	return ss.str();
}

/*-----------------------------------------------------------------------------
    get_path_from_fd - this function return the full path of an opened fd
    or "" otherwise.
-----------------------------------------------------------------------------*/
std::string monitor::get_path_from_fd(unsigned long fd)
{
	char                                 cmd[500];
	sprintf(cmd, R"(ls -al /proc/%d/fd | sed 's/.*[0-9][0-9]:[0-9][0-9] //' | grep "\->" | sed 's/ -> /:/')", mvee::active_monitor->variants[0].variantpid);

	std::stringstream                    ss(mvee::log_read_from_proc_pipe(cmd, nullptr));
	std::string                          line;
	unsigned long                        tmp_fd;
	char                                 path[500];

	// read /proc/<pid>/fd and get the corresponding path of the given fd
	while (std::getline(ss, line, '\n')) {
		if (sscanf(line.c_str(), "%lu:%s", &tmp_fd, path) == 2) {
			if (tmp_fd == fd) {
				debugf("Fd %lu corresponds to %s\n", fd, path);
				return std::string(path);
			}
		}
	}

	return "";
}

/*-----------------------------------------------------------------------------
    get_full_path - this function also supports the [syscall]at family
    but it can resolve normal paths as well (if dirfd == AT_FDCWD)
-----------------------------------------------------------------------------*/
std::string monitor::get_full_path(unsigned long dirfd, void* path_ptr)
{
	std::stringstream ss;

	// fetch the path and check if it's absolute...
	std::string tmp_path = rw::read_string(mvee::active_monitor->variants[0].variantpid, path_ptr, 0);

	if (tmp_path.length() > 0 && tmp_path.find("/proc/self/") == 0) {
		ss << "/proc/" << mvee::active_monitor->variants[0].varianttgid << "/" << tmp_path.substr(strlen("/proc/self/"));
	}
	else if (tmp_path.length() > 0 && tmp_path[0] == '/') {
		// it's absolute so we can ignore the dirfd...
		ss << tmp_path;
	}
	else {
		// relative path... fetch the base path
		if ((int)dirfd == AT_FDCWD) {
			char proc_path[100];
			char cwd_path[2048];

			memset(cwd_path, 0, 2048);
			sprintf(proc_path, "/proc/%d/cwd", mvee::active_monitor->variants[0].varianttgid);
			if (readlink(proc_path, cwd_path, 2048) != -1)
				ss << cwd_path;
		}
		else {
			std::string dirfd_path = get_path_from_fd(dirfd);
			ss << dirfd_path;
		}

		if (tmp_path.length() > 0) {
			if (ss.str()[ss.str().length()-1] != '/')
				ss << '/';
			ss << tmp_path;
		}
	}

	return mvee::os_normalize_path_name(ss.str());
}
