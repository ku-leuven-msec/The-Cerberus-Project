/*
 * Cerberus PKU-based Sandbox
 *
 * Check Cerberus/cerberus_ReMon/README.md for licensing terms.
 */

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include <elf.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/shm.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <csignal>
#include <cassert>
#include <cerrno>
#include <fcntl.h>
#include <cstring>
#include <unistd.h>
#include <sstream>
#include <algorithm>
#include <libgen.h>
#include <cstdarg>
#include <iostream>
#include <cctype>
#include "MVEE.h"
#include "MVEE_monitor.h"
#include "MVEE_memory.h"
#include "MVEE_logging.h"
#include "MVEE_syscalls.h"
#include "MVEE_private_arch.h"
#include "MVEE_macros.h"
#include "MVEE_interaction.h"

/*-----------------------------------------------------------------------------
    Static Member Initialization
-----------------------------------------------------------------------------*/
int                                    mvee::numvariants                         = 0;
std::vector<std::string>               mvee::variant_ids;
__thread monitor*                      mvee::active_monitor                      = NULL;
__thread int                           mvee::active_monitorid                    = 0;
int                                    mvee::shutdown_signal                     = 0;
std::map<unsigned long, unsigned char> mvee::syslocks_table;
pthread_mutex_t                        mvee::global_lock                         = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
pthread_cond_t                         mvee::global_cond                         = PTHREAD_COND_INITIALIZER;
bool                                   mvee::should_garbage_collect              = false;
std::vector<monitor*>                  mvee::dead_monitors;
std::vector<monitor*>                  mvee::active_monitors;
std::vector<monitor*>                  mvee::inactive_monitors;
std::map<pid_t, std::vector<pid_t> >   mvee::variant_pid_mapping;
std::map<int, monitor*>                mvee::monitor_id_mapping;
int                                    mvee::next_monitorid                      = 0;
std::vector<detachedvariant*>          mvee::detachlist;
std::string                            mvee::orig_working_dir;
pid_t                                  mvee::process_pid                         = 0;
__thread pid_t                         mvee::thread_pid                          = 0;
std::map<std::string, std::string>     mvee::interp_map;
volatile unsigned long                 mvee::can_run                             = 0;
std::string                            mvee::config_file_name                    = "";
bool                                   mvee::config_show                         = false;
std::string                            mvee::config_variant_set                  = "default";
Json::Value                            mvee::config;
Json::Value*                           mvee::config_monitor                      = NULL;
Json::Value*                           mvee::config_variant_global               = NULL;
Json::Value*                           mvee::config_variant_exec                 = NULL;
pthread_mutex_t                        mvee::special_lock                        = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
std::unordered_set<unsigned long>      mvee::special_files;
/*-----------------------------------------------------------------------------
    Prototypes
-----------------------------------------------------------------------------*/
void mvee_mon_external_termination_request(int sig);

/*-----------------------------------------------------------------------------
  strsplit
------------------------------------------------------------------------------*/
std::deque<std::string> mvee::strsplit(const std::string &s, char delim)
{
	std::stringstream       ss(s);
	std::string             item;
	std::deque<std::string> elems;

	while (std::getline(ss, item, delim))
		elems.push_back(item);

	return elems;
}
/*-----------------------------------------------------------------------------
  str_ends_with
------------------------------------------------------------------------------*/
bool mvee::str_ends_with(std::string& search_in_str, const char* suffix)
{
	std::string search_for_str(suffix);
	return search_in_str.size() >= search_for_str.size() && search_in_str.rfind(search_for_str) == (search_in_str.size()-search_for_str.size());
}

/*-----------------------------------------------------------------------------
    mvee_strdup - returns a string copy allocated with new[] instead of
    malloc... This is just here to keep valgrind happy
-----------------------------------------------------------------------------*/
char* mvee::strdup(const char* orig)
{
	if (!orig)
		return NULL;

	int   orig_len   = strlen(orig);
	char* new_string = new char[orig_len+1];
	memcpy(new_string, orig, strlen(orig)+1);
	return new_string;
}

/*-----------------------------------------------------------------------------
    upcase
-----------------------------------------------------------------------------*/
std::string mvee::upcase(const char* lower_case_string)
{
	std::string out(lower_case_string);
	std::transform(out.begin(), out.end(), out.begin(), ::toupper);
	return out;
}

/*-----------------------------------------------------------------------------
    mvee_old_sigset_to_new_sigset
-----------------------------------------------------------------------------*/
sigset_t mvee::old_sigset_to_new_sigset(unsigned long old_sigset)
{
	sigset_t set;
	sigemptyset(&set);

	for (int i = 1; i < 32; ++i) {
		if ((old_sigset >> i) & 0x1)
			sigaddset(&set, i);
	}

	return set;
}

/*-----------------------------------------------------------------------------
    os_get_orig_working_dir
-----------------------------------------------------------------------------*/
std::string mvee::os_get_orig_working_dir()
{
	if (mvee::orig_working_dir == "") {
		char* cwd = getcwd(NULL, 0);
		mvee::orig_working_dir = std::string(cwd);
		free(cwd);
	}
	return mvee::orig_working_dir;
}

/*-----------------------------------------------------------------------------
    os_get_mvee_root_dir
-----------------------------------------------------------------------------*/
std::string mvee::os_get_mvee_root_dir()
{
	if ((*mvee::config_monitor)["root_path"].isNull() || strlen((*mvee::config_monitor)["root_path"].asCString()) == 0) {
		char cmd[500];
		sprintf(cmd, "readlink -f /proc/%d/exe | sed 's/\\(.*\\)\\/.*/\\1\\/..\\/..\\/..\\//' | xargs readlink -f | tr -d '\\n'", getpid());
		std::string out = mvee::log_read_from_proc_pipe(cmd, NULL);

		if (out != "") {
			if (out.length() < 2) {
				warnf("root path does not make sense. Cerberus is possibly running under valgrind/gdb\n");
				// warnf("using /home/stijn/MVEE as the root dir instead\n");
				// (*mvee::config_monitor)["root_path"] = "/home/stijn/MVEE";
			}
			else {
				(*mvee::config_monitor)["root_path"] = out;
			}
		}
	}

	return (*mvee::config_monitor)["root_path"].asString();
}

/*-----------------------------------------------------------------------------
    os_check_ptrace_scope - Ubuntu's Yama LSM is currently broken w.r.t.
    ptracing. I've reported the bug here but afaik it hasn't been fixed yet:
    https://lkml.org/lkml/2014/12/24/196

    As a temporary fix, this function will attempt to disable Yama's ptrace
    checking.
-----------------------------------------------------------------------------*/
void mvee::os_check_ptrace_scope()
{
	std::string yama = mvee::log_read_from_proc_pipe("/sbin/sysctl kernel.yama.ptrace_scope", NULL);

	// If we're not running on ubuntu, we won't get any feedback through stdout
	if (yama == "")
		return;

	if (yama.find("kernel.yama.ptrace_scope = 1") == 0) {
		printf("============================================================================================================================\n");
		printf("It seems that you are running Ubuntu with the Yama Linux Security Module and Yama's ptrace scope set to SCOPE_RELATIONAL.\n");
		printf("In the current Yama implementation, SCOPE_RELATIONAL causes problems for multi-process variants.\n");
		printf("Cerberus will therefore try to disable yama's ptrace introspection using:\n\n");
		printf("sudo sysctl -w kernel.yama.ptrace_scope=0\n\n");
		printf("You can read more about this bug on the Linux Kernel Mailing list in the following thread:\n");
		printf("https://lkml.org/lkml/2014/12/24/196\n\n");

		yama = mvee::log_read_from_proc_pipe("sudo sysctl -w kernel.yama.ptrace_scope=0", NULL);

		if (yama.find("kernel.yama.ptrace_scope = 0") != 0)
			printf("Failed to disable yama's ptrace introspection. You probably don't have sudo rights. Please have your administrator fix this!\n");
		else
			printf("Disabled yama!\n");
		printf("============================================================================================================================\n");
	}
}

/*-----------------------------------------------------------------------------
    mvee_getpid
-----------------------------------------------------------------------------*/
int mvee::os_getpid()
{
	if (!mvee::process_pid)
		mvee::process_pid = syscall(__NR_getpid);

	return mvee::process_pid;
}

/*-----------------------------------------------------------------------------
    mvee_gettid
-----------------------------------------------------------------------------*/
int mvee::os_gettid()
{
	if (!mvee::thread_pid)
		mvee::thread_pid = syscall(__NR_gettid);

	return mvee::thread_pid;
}

/*-----------------------------------------------------------------------------
    os_get_interp - get the full path to the program interpreter for this
    architecture.
-----------------------------------------------------------------------------*/
std::string mvee::os_get_interp()
{
	std::stringstream ss;
	ss << MVEE_ARCH_INTERP_PATH << MVEE_ARCH_INTERP_NAME;
	return ss.str();
}

/*-----------------------------------------------------------------------------
    os_can_load_indirect -
-----------------------------------------------------------------------------*/
bool mvee::os_can_load_indirect(std::string& file)
{
	std::string cmd = "/usr/bin/readelf -d " + file + " 2>&1";
	std::string dyn = mvee::log_read_from_proc_pipe(cmd.c_str(), NULL);

	// invalid ELF file
	if (dyn.find("Error") != std::string::npos)
		return true;

	// dynamic section found => We can use the LD_Loader
	if (dyn.find("There is no dynamic section in this file.") == std::string::npos)
		return true;

	cmd = "/usr/bin/readelf -h " + file + " | grep Type 2>&1";
	std::string header = mvee::log_read_from_proc_pipe(cmd.c_str(), NULL);

	// statically linked, but PIE compiled
	if (header.find("DYN") != std::string::npos)
		return true;

	// statically linked and position dependent => can't use LD_Loader
	return false;
}

/*-----------------------------------------------------------------------------
    os_get_interp_for_file - if file is a script, return the interpreter for
    that script
-----------------------------------------------------------------------------*/
void mvee::os_register_interp(std::string& file, const char* interp)
{
	MutexLock lock(&mvee::global_lock);
	if (interp_map.find(file) != interp_map.end())
		interp_map.insert(std::pair<std::string, std::string>(file, interp));
}

bool mvee::os_add_interp_for_file(std::deque<char*>& add_to_queue, std::string& file)
{
	{
		MutexLock lock(&mvee::global_lock);
		auto      it = interp_map.find(file);

		if (it != interp_map.end()) {
			if (it->second.length() != 0)
				add_to_queue.push_front(mvee::strdup(it->second.c_str()));
			return true;
		}
	}

	std::string cmd       = "/usr/bin/file -L " + file + " | grep -v ERROR";
	std::string file_type = mvee::log_read_from_proc_pipe(cmd.c_str(), NULL);

	if (file_type == "")
		return false;

	if (file_type.find("ELF") != std::string::npos) {
		os_register_interp(file, "");
		return true;
	}

	// the file exists but is not ELF
	cmd = "/usr/bin/head -n1 " + file;
	std::string interp    = mvee::log_read_from_proc_pipe(cmd.c_str(), NULL);
	if (interp.find("#!") == 0) {
		interp.erase(interp.begin(),                                  interp.begin()+1);
		interp.erase(interp.begin(),                                  interp.begin()+interp.find("/"));
		interp.erase(std::remove(interp.begin(), interp.end(), '\n'), interp.end());
		std::deque<std::string> tokens = mvee::strsplit(interp, ' ');
		while (tokens.size() > 0) {
			add_to_queue.push_front(mvee::strdup(tokens.back().c_str()));
			tokens.pop_back();
		}
		return true;
	}

	// can find an interpreter there. Try a set of known extensions
	if (mvee::str_ends_with(file, ".sh")) {
		add_to_queue.push_front(mvee::strdup("/bin/bash"));
		os_register_interp(file, "/bin/bash");
		return true;
	}
	else if (mvee::str_ends_with(file, ".rb")) {
		add_to_queue.push_front(mvee::strdup("/usr/bin/ruby"));
		os_register_interp(file, "/usr/bin/ruby");
		return true;
	}

	warnf("Can't determine the appropriate interpreter for file: %s\n", file.c_str());
	return false;
}

/*-----------------------------------------------------------------------------
    os_get_mvee_ld_loader - get the full path to the MVEE_LD_Loader for this
    architecture.
-----------------------------------------------------------------------------*/
std::string mvee::os_get_mvee_ld_loader()
{
	std::stringstream ss;
	ss << (*mvee::config_monitor)["root_path"].asString() << MVEE_LD_LOADER_PATH << MVEE_LD_LOADER_NAME;
	return ss.str();
}

/*-----------------------------------------------------------------------------
    os_reset_envp
-----------------------------------------------------------------------------*/
void mvee::os_reset_envp()
{
	// Dirty hack to force initialization of the environment.
	// Without this we'll get allocation behavior mismatches everywhere!
	// Even in GCC!!
	putenv((char*)"THIS=SILLY");
	putenv((char*)"LD_PRELOAD");
	putenv((char*)"SPEC");
	putenv((char*)"SPECPERLLIB");
	putenv((char*)"LD_LIBRARY_PATH");
	// putenv((char*)"SPECPATH");
	// putenv((char*)"SPECLIBPATH");
	// putenv((char*)"SPECPROFILE");
	// putenv((char*)"SPECEXT");
}

/*-----------------------------------------------------------------------------
    os_normalize_path_name
-----------------------------------------------------------------------------*/
std::string mvee::os_normalize_path_name(std::string path)
{
	char* tmp = realpath(path.c_str(), NULL);

	if (!tmp) {
		if (errno == ENOENT) {
			auto slash = path.rfind('/');
			if (slash != std::string::npos) {
				auto dir_only = path.substr(0, slash);
				auto file = path.substr(slash);
				auto normalized_dir = os_normalize_path_name(dir_only);
				return normalized_dir + file;
			}

			return path;
		}
		else {
			return path;
		}
	}
	{
		std::string result(tmp);
		free(tmp);
		return result;
	}
}

/*-----------------------------------------------------------------------------
    lock
-----------------------------------------------------------------------------*/
void mvee::lock()
{
	pthread_mutex_lock(&mvee::global_lock);
}

/*-----------------------------------------------------------------------------
    unlock
-----------------------------------------------------------------------------*/
void mvee::unlock()
{
	pthread_mutex_unlock(&mvee::global_lock);
}

/*-----------------------------------------------------------------------------
    request_shutdown -
-----------------------------------------------------------------------------*/
void mvee::request_shutdown()
{
	mvee::lock();
	mvee::shutdown_signal = SIGINT;
	mvee::unlock();
	pthread_cond_broadcast(&mvee::global_cond);
}

/*-----------------------------------------------------------------------------
    shutdown - Safely shuts down the MVEE
-----------------------------------------------------------------------------*/
void mvee::shutdown()
{
	/*
	retarded hack here. We have no way
	to unblock monitors that are waitpid'ing UNLESS we trigger an event that
	causes the waitpid to return

	=> we send a SIGALRM to one of the variants
	*/
	mvee::lock();
	for (auto it : mvee::active_monitors)
		it->signal_shutdown();
	for (auto it : mvee::inactive_monitors) {
		// no need to send SIGUSR1. This monitor is already waiting to be shut down
		it->monitor_tid = 0; 
		it->signal_shutdown();
	}
	mvee::unlock();

	// wait for all monitors to terminate
	while (1) {
		mvee::lock();
		if (mvee::active_monitors.size() == 0 && mvee::inactive_monitors.size() == 0) {
			mvee::unlock();
			break;
		}
		mvee::unlock();
		sched_yield();
	}

	printf("all monitors terminated\n");
	mvee::log_fini(true);
	exit(0);
}

/*-----------------------------------------------------------------------------
    garbage_collect -
-----------------------------------------------------------------------------*/
void mvee::garbage_collect()
{
	std::vector<monitor*> local_gclist;

	{
		MutexLock lock(&mvee::global_lock);

		mvee::should_garbage_collect = false;

		// copy all dead monitors to a local gclist first and then clean them up
		// without locking the global state...
		while (mvee::dead_monitors.size() > 0) {
			auto mon = mvee::dead_monitors.back();
			local_gclist.push_back(mon);
			mvee::dead_monitors.pop_back();
		}
	}

	while (local_gclist.size() > 0) {
		auto mon = local_gclist.back();

		if (mvee::shutdown_signal == 0)
		mon->join_thread();

		logf("garbage collected monitor: %d\n", mon->monitorid);
		SAFEDELETE(mon);
		local_gclist.pop_back();
	}
}

/*-----------------------------------------------------------------------------
    is_multiprocess
-----------------------------------------------------------------------------*/
bool mvee::is_multiprocess()
{
	pid_t     prev_tgid = 0;
	int       num_tgids = 0;

	MutexLock lock(&mvee::global_lock);
	for (auto it : mvee::active_monitors) {
		pid_t tgid;
		if ((tgid = it->get_mastertgid()) != prev_tgid) {
			if (num_tgids++)
				return true;
			prev_tgid = tgid;
		}
	}

	return false;
}

/*-----------------------------------------------------------------------------
    get_next_monitorid
-----------------------------------------------------------------------------*/
int mvee::get_next_monitorid()
{
	MutexLock lock(&mvee::global_lock);
	return mvee::next_monitorid++;
}

/*-----------------------------------------------------------------------------
    add_detached_variant
-----------------------------------------------------------------------------*/
void mvee::add_detached_variant(detachedvariant* variant)
{
	MutexLock lock(&mvee::global_lock);
	mvee::detachlist.push_back(variant);
}

/*-----------------------------------------------------------------------------
    remove_detached_variant - returns the variant that was removed
-----------------------------------------------------------------------------*/
detachedvariant* mvee::remove_detached_variant(pid_t variantpid)
{
	MutexLock lock(&mvee::global_lock);

	for (std::vector<detachedvariant*>::iterator it = mvee::detachlist.begin(); it != mvee::detachlist.end(); ++it) {
		if ((*it)->variantpid == variantpid) {
			detachedvariant* variant = *it;
			mvee::detachlist.erase(it);
			pthread_cond_broadcast(&mvee::global_cond);
			return variant;
		}
	}

	return NULL;
}

/*-----------------------------------------------------------------------------
    have_detached_variants - checks whether the specified monitor has detached
    from processes that have not been attached to another monitor yet
-----------------------------------------------------------------------------*/
bool mvee::have_detached_variants(monitor* mon)
{
	MutexLock lock(&mvee::global_lock);

	for (std::vector<detachedvariant*>::iterator it = mvee::detachlist.begin(); it != mvee::detachlist.end(); ++it) {
		if ((*it)->parentmonitorid == mon->monitorid)
			return true;
	}

	return false;
}

/*-----------------------------------------------------------------------------
    have_pending_variants - counts the number of variants that are waiting to
    be attached to the specified monitor
-----------------------------------------------------------------------------*/
int mvee::have_pending_variants(monitor* mon)
{
	int       cnt = 0;
	MutexLock lock(&mvee::global_lock);

	for (std::vector<detachedvariant*>::iterator it = mvee::detachlist.begin(); it != mvee::detachlist.end(); ++it) {
		if ((*it)->parent_has_detached && (*it)->new_monitor == mon)
			cnt++;
	}

	return cnt;
}

/*-----------------------------------------------------------------------------
    set_should_check_multithread_state
-----------------------------------------------------------------------------*/
void mvee::set_should_check_multithread_state(int monitorid)
{
	MutexLock lock(&mvee::global_lock);
}

/*-----------------------------------------------------------------------------
    register_variants
-----------------------------------------------------------------------------*/
void mvee::register_variants(std::vector<pid_t>& pids)
{
	MutexLock lock(&mvee::global_lock);
	mvee::variant_pid_mapping.erase(pids[0]);
	mvee::variant_pid_mapping.insert(std::pair<pid_t, std::vector<pid_t> >(pids[0], pids));
}

/*-----------------------------------------------------------------------------
    register_monitor
-----------------------------------------------------------------------------*/
void mvee::register_monitor(monitor* mon)
{
	MutexLock lock(&mvee::global_lock);
	mvee::monitor_id_mapping.insert(std::pair<int, monitor*>(mon->monitorid, mon));
	mvee::active_monitors.push_back(mon);
    mon->signal_registration();
}

/*-----------------------------------------------------------------------------
    unregister_monitor
-----------------------------------------------------------------------------*/
void mvee::unregister_monitor(monitor* mon, bool move_to_dead_monitors)
{
	bool should_shutdown = false;

	{
		MutexLock lock(&mvee::global_lock);
		auto it = monitor_id_mapping.find(mon->monitorid);
		if (it != monitor_id_mapping.end())
			monitor_id_mapping.erase(it);
		auto it2 = std::find(active_monitors.begin(), active_monitors.end(), mon);
		if (it2 != active_monitors.end())
			active_monitors.erase(it2);

		if (move_to_dead_monitors) {
			auto it3 = std::find(inactive_monitors.begin(), inactive_monitors.end(), mon);
			if (it3 != inactive_monitors.end())
				inactive_monitors.erase(it3);

			dead_monitors.push_back(mon);
			should_garbage_collect = true;
		}
		else {
			inactive_monitors.push_back(mon);
		}

		if (active_monitors.size() <= 0)
			should_shutdown = true;

		pthread_cond_broadcast(&mvee::global_cond);

		if (mon == mvee::active_monitor)
			mvee::active_monitor = NULL;
	}

	if (should_shutdown)
		mvee::request_shutdown();
}

/*-----------------------------------------------------------------------------
    mvee_mon_external_termination_request - signal handler for the primary thread
-----------------------------------------------------------------------------*/
void mvee_mon_external_termination_request(int sig)
{
	if (mvee::active_monitorid == -1) {
		printf("EXTERNAL TERMINATION REQUEST - MONITORID: %d\n", mvee::active_monitorid);
		if (!mvee::shutdown_signal)
				mvee::request_shutdown();
		else
			exit(0);
	}
	else {
		// do nothing. We just use a signal to unblock any blocking calls
		// mvee_mon_return(true);
		printf("TERMINATION REQUEST - MONITORID: %d\n", mvee::active_monitorid);
		mvee::active_monitor->signal_shutdown();
	}
}

/*-----------------------------------------------------------------------------
    start_monitored - forks off the variant, prepare it
    for tracing, starts it, ... Then the monitor sets up signal handlers,
    starts the timer and immediately resumes the variant.
-----------------------------------------------------------------------------*/
void mvee::start_monitored()
{
	std::vector<pid_t> procs(mvee::numvariants);
	sigset_t           set;
	sigemptyset(&set);
	sigaddset(&set, SIGINT);
	pthread_sigmask(SIG_BLOCK, &set, nullptr);

	procs[0] = fork();
	if (procs[0]) {
		mvee::log_init();
		mvee::special_init();

		logf("======================================================\n");
		logf("             \"Cerberus PKU-based Sandbox\"           \n");
		logf("======================================================\n");

		sigset_t  set;
		sigemptyset(&set);
		sigaddset(&set, SIGINT);
		pthread_sigmask(SIG_UNBLOCK, &set, nullptr);

		mvee::active_monitor = new monitor(procs);

		// Install signal handlers for SIGINT and SIGQUIT so we can shut down safely after CTRL+C
		struct sigaction sigact{};
		sigact.sa_handler = mvee_mon_external_termination_request;
		sigemptyset(&set);
		sigact.sa_mask    = set;
		sigact.sa_flags   = 0;

		sigaction(SIGINT, &sigact, nullptr);
		sigaction(SIGQUIT, &sigact, nullptr);

		sigact.sa_handler = mvee_mon_external_termination_request;
		sigaction(SIGUSR2, &sigact, nullptr);

		interaction::mvee_wait_status status{};
		if (!interaction::wait(procs[0], status, false, false, false)) {
			warnf("Failed to wait for children - errno: %s - status: %s\n",
				  getTextualErrno(errno), getTextualMVEEWaitStatus(status).c_str());
			exit(-1);
			return;
		}

		if (status.reason == STOP_SIGNAL)
			if (!interaction::detach(procs[0]))
				warnf("Failed to detach from variant %d\n", 0);

		mvee::register_monitor(mvee::active_monitor);

		// everything is set up and ready to go...
		mvee::active_monitor   = nullptr;
		mvee::active_monitorid = -1;
		while (true) {
			bool should_gc = false;

			mvee::lock();
			if (mvee::shutdown_signal) {
				mvee::unlock();
				mvee::shutdown();
				return;
			}

			pthread_cond_wait(&mvee::global_cond, &mvee::global_lock);
			should_gc = mvee::should_garbage_collect;
			mvee::unlock();

			if (should_gc)
				mvee::garbage_collect();
		}
	}
	// If the process is a variant, prepare it for tracing
	else {
		mvee::setup_env();

		// Place the new variant under supervision of the main thread of the
		// monitor process.
		if (!interaction::accept_tracing())
			fprintf(stderr, "Couldn't accept tracing\n");

		// Stop the variant so we can detach the main monitor thread.
		kill(getpid(), SIGSTOP);

		// Wait in a busy loop while we wait for the designated monitor
		// thread to attach
		while (!mvee::can_run)
			;

		// The monitor thread is now attached. It is now safe to execve
		start_variant();
	}
}

/*-----------------------------------------------------------------------------
    usage
-----------------------------------------------------------------------------*/
static void usage()
{
	printf("======================================================\n");
	printf("             \"Cerberus PKU-based Sandbox\"           \n");
	printf("======================================================\n\n");
	printf("Legacy Mode Syntax:\n");
	printf("./MVEE [Builtin Configuration Number (see MVEE_config.cpp)] [MVEE Options]\n\n");
	printf("RAVEN Mode Syntax:\n");
	printf("./MVEE -s <variant set> -f <config file> [MVEE Options] -- [Program Args]\n\n");
	printf("MVEE Options:\n");
	printf("> -s <variant set> : run the specified variant set. If this option is omitted, Cerberus will launch variant set \"default\". NOTE: This option is ignored in legacy mode.\n");
	printf("> -f <file name>   : use the monitor config in the specified file. If this option is omitted, the config will be read from MVEE.ini. NOTE: If the MVEE is run in legacy mode, then any options in the builtin config take precedence over the settings in the config file.\n");
	printf("> -N <number of variants> : sets the number of variants. In RAVEN mode, this option can override the number of variants specified in the config file.\n");
	printf("> -n : no monitoring. Variant processes are executed without supervision. Useful for benchmarking.\n");
	printf("> -p : use performance counters to track cache and synchronization behavior of the variants.\n");
	printf("> -o : log everything to stdout, as well as the log files. This flag is ignored if the MVEE is compiled with MVEE_BENCHMARK defined in MVEE_build_config.h\n");
	printf("> -c : show the contents of the json config file after command line processing.\n");
	printf("> In legacy mode, all arguments including and following the first non-option are passed as program arguments to the variants\n");
}

/*-----------------------------------------------------------------------------
    add_argv
-----------------------------------------------------------------------------*/
void mvee::add_argv(const char* arg, bool first_extra_arg)
{
	bool merge_extra_args = 
		!(*mvee::config_variant_global)["merge_extra_args"].isNull() &&
		(*mvee::config_variant_global)["merge_extra_args"].asBool();

	// Add to global exec arguments
	if (!(*mvee::config_variant_exec)["argv"])
		(*mvee::config_variant_exec)["argv"][0] = std::string(arg);
	else if (!merge_extra_args || first_extra_arg)
		(*mvee::config_variant_exec)["argv"].append(std::string(arg));
	else {
		auto str = (*mvee::config_variant_exec)["argv"][(*mvee::config_variant_exec)["argv"].size() - 1].asCString();
		std::stringstream ss;
		ss << str << " " << arg;
		(*mvee::config_variant_exec)["argv"][(*mvee::config_variant_exec)["argv"].size() - 1] = ss.str();
	}

	for (auto variant_spec : mvee::config["variant"]["specs"]) {
		if (!variant_spec["argv"])
			variant_spec["argv"][0] = std::string(arg);
		else if (!merge_extra_args || first_extra_arg)
			variant_spec["argv"].append(std::string(arg));
		else {
			auto str = (variant_spec)["argv"][(variant_spec)["argv"].size() - 1].asCString();
			std::stringstream ss;
			ss << str << " " << arg;
			(variant_spec)["argv"][(variant_spec)["argv"].size() - 1] = ss.str();
		}
	}
}

/*-----------------------------------------------------------------------------
    process_opts
-----------------------------------------------------------------------------*/
bool mvee::process_opts(int argc, char** argv, bool add_args)
{
	int opt;
	bool stop = false;
	while ((opt = getopt(argc, argv, ":s:f:N:npoc")) != -1 && !stop) {
		switch(opt) {
			case ':': // missing arg
				if (!strcmp(argv[optind+1], "--")) {
					stop = true;
					break;
				}
				else {
					usage();
					return false;
				}
			case 's':
				mvee::config_variant_set = std::string(optarg);
				break;
			case 'o':
				(*mvee::config_monitor)["log_to_stdout"] = true;
				break;
			case 'N':
				mvee::numvariants = strtoll(optarg, NULL, 10);
				break;
			case 'p':
				(*mvee::config_variant_global)["performance_counting_enabled"] = true;
				break;
			case 'f': // we've already parsed the config file name
				break;
			case 'c':
				mvee::config_show = true;
				break;
			default:
				stop = true;
				break;
		}
	}

	if (add_args) {
		bool first_extra_arg = true;

		for (int i = optind; i < argc; ++i) {
			add_argv(argv[i], first_extra_arg);
			first_extra_arg = false;
		}
	}

	return true;
}

/*-----------------------------------------------------------------------------
    isnumeric
-----------------------------------------------------------------------------*/
static bool isnumeric(const char* str)
{
	while(*str) {
		char c = *str;
		if (c < '0' || c > '9')
			return false;
		str++;
	}
	return true;
}

/*-----------------------------------------------------------------------------
    Main - parse command line opts and launch monitor/variants
-----------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
	bool legacy_mode = true;

	if (argc <= 2) {
		usage();
		return 0;
	}
	else {
		mvee::os_check_ptrace_scope();
		mvee::init_syslocks();

		int dash_pos, i = 1, builtin = 0;

		// Determine the mode we're launching in
		for (dash_pos = 0; dash_pos < argc; ++dash_pos) {
			if (!strcmp(argv[dash_pos], "--")) {
				legacy_mode = false;
				break;
			}
		}

		// look for -f first and initialize the config
		i = legacy_mode ? 2 : 1;
		for (; i < argc; ++i) {
			if (!strcmp(argv[i], "-f")) {
				if (i + 1 < argc)
					mvee::config_file_name = std::string(argv[i + 1]);
				else
					warnf("You must pass a filename after -f! Using MVEE.ini instead.\n");
				break;
			}
		}

		// Use default MVEE.ini if needed
		if (mvee::config_file_name.size() == 0) {
			char path[1024];
			memset(path, 0, 1024);

			if (readlink("/proc/self/exe", path, 1024) > 0) {
				std::string str(path);
				if (str.rfind("/") != std::string::npos)
					mvee::config_file_name = str.substr(0, str.rfind("/") + 1) + "MVEE.ini";
				else
					mvee::config_file_name = "MVEE.ini";
			}
		}

		// Initialize the config before processing further cmdline options
		mvee::init_config();
		mvee::os_get_orig_working_dir();
		mvee::os_get_mvee_root_dir();
		mvee::os_reset_envp();

		if (!legacy_mode) {
			// process all options before the --
			if (!mvee::process_opts(argc, argv, false))
				return -1;
			
			// Process everything after the "--" as program arguments
			bool first_extra_arg = true;
            for (i = dash_pos + 1; i < argc; ++i)
			{
				mvee::add_argv(argv[i], first_extra_arg);
				first_extra_arg = false;
			}
		}
		else {
			if (!isnumeric(argv[1])) {
				usage();
				return -1;
			}

			// discard any conflicting args we may have read from the config
			mvee::config["variant"]["sets"].clear();
			mvee::config["variant"]["specs"].clear();
			if (!(*mvee::config_variant_exec)["path"].isNull() &&
				(*mvee::config_variant_exec)["path"].isArray()) // it shouldn't be, but who knows...
				(*mvee::config_variant_exec)["path"];
			if (!(*mvee::config_variant_exec)["argv"].isNull() &&
				(*mvee::config_variant_exec)["argv"].isArray())
				(*mvee::config_variant_exec)["argv"].clear();
			if (!(*mvee::config_variant_exec)["env"].isNull() &&
				(*mvee::config_variant_exec)["env"].isArray())
				(*mvee::config_variant_exec)["env"].clear();
			
			builtin = atoi(argv[1]);

			// Pretend that argv[1] is the new argv[0]
			if (!mvee::process_opts(argc - 1, &argv[1], true))
				return -1;

			mvee::set_builtin_config(builtin);
		}
	}

	// select variants
	if (!legacy_mode) {
		if (!mvee::config["variant"]["sets"][mvee::config_variant_set]) {
			printf("Couldn't find variant set %s\n", mvee::config_variant_set.c_str());
			return -1;
		}

		int limit = mvee::numvariants ? mvee::numvariants : mvee::config["variant"]["sets"][mvee::config_variant_set].size(), i = 0;
		auto it = mvee::config["variant"]["sets"][mvee::config_variant_set].begin();
		for (; i < limit; ++i) {
			if (it == mvee::config["variant"]["sets"][mvee::config_variant_set].end())
				it = mvee::config["variant"]["sets"][mvee::config_variant_set].begin();

			if (it == mvee::config["variant"]["sets"][mvee::config_variant_set].end())
				break;

			auto variant = *it;

			// check if a variant.specs config exists for the specified variant
			if (!mvee::config["variant"]["specs"][variant.asString()]) {
				printf("Couldn't find config for variant %s in set %s\n",
					   variant.asString().c_str(), mvee::config_variant_set.c_str());
				return -1;
			}
			mvee::variant_ids.push_back(variant.asString());

			it++;
		}

		mvee::numvariants = mvee::variant_ids.size();
	}
	else {
		// initialize variant ids
		if (mvee::numvariants != 0) {
			mvee::variant_ids.resize(mvee::numvariants);
			std::fill(mvee::variant_ids.begin(), mvee::variant_ids.end(), "null");
		}
	}

	if (mvee::numvariants <= 0) {
		printf("Can't run Cerberus with %d variants!\n", mvee::numvariants);
		usage();
		return -1;
	}

	if (mvee::config_show) {
		Json::StyledWriter writer;
		std::cout << "Using config: " << writer.write(mvee::config) << "\n";
	}

	mvee::start_monitored();

	return 0;
}
