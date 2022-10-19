/*
 * Cerberus PKU-based Sandbox
 *
 * Check Cerberus/cerberus_ReMon/README.md for licensing terms.
 */

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include <sys/mman.h>
#include <sys/shm.h>
#include <cstring>
#include <sstream>
#include <sys/types.h>
#include <sys/wait.h>
#include "MVEE.h"
#include "MVEE_monitor.h"
#include "MVEE_mman.h"
#include "MVEE_macros.h"
#include "MVEE_signals.h"
#include "MVEE_syscalls.h"
#include "MVEE_memory.h"
#include "MVEE_logging.h"
#include "MVEE_interaction.h"

/*-----------------------------------------------------------------------------
    overwritten_syscall_arg
-----------------------------------------------------------------------------*/
overwritten_syscall_arg::overwritten_syscall_arg()
		: syscall_arg_num (0)
		, arg_old_value (0)
{
}

overwritten_syscall_arg::~overwritten_syscall_arg()
{
}

/*-----------------------------------------------------------------------------
    variantstate class
-----------------------------------------------------------------------------*/
variantstate::variantstate()
	: variantpid (0)
	, prevcallnum (0)
	, callnum (0)
	, call_flags (0)
	, return_value (0)
	, call_type (0)
	, regs_valid (false)
	, return_valid (false)
	, restarted_syscall (false)
	, restarting_syscall (false)
	, variant_terminated (false)
	, variant_attached (false)
	, variant_resumed (false)
	, current_signal_ready (false)
	, have_overwritten_args (false)
	//, active_executable_page_with_dangerous_instructions (0)
	, varianttgid (0)
	, pendingpid (0)
	, infinite_loop_ptr (0)
	, callnumbackup (0)
	, config (NULL)
	, syscall_jump (nullptr)
	, get_pku_domain_jump (nullptr)
	, special_page (nullptr)
	, first_syscall_after_execve (false)
{
	memset(&regs, 0, sizeof(PTRACE_REGS));
	sigemptyset(&last_sigset);
	memset(&regsbackup, 0, sizeof(PTRACE_REGS));
	memset(hw_bps,      0, 4*sizeof(unsigned long));
	memset(hw_bps_type, 0, 4*sizeof(unsigned char));
	memset(tid_address, 0, 2*sizeof(void*));
}

variantstate::~variantstate()
{
}

/*-----------------------------------------------------------------------------
    is_group_shutting_down
-----------------------------------------------------------------------------*/
bool monitor::is_group_shutting_down()
{
	if (!set_mmap_table || set_mmap_table->thread_group_shutting_down)
		return true;
	return false;
}

/*-----------------------------------------------------------------------------
    monitor - creates and initializes a new monitor

    if the new monitor is a primary (i.e. monitor 0), the monitor is created
    with no variants. This monitor gets empty fd/mmap/shm/sighand tables and
    is not registered automatically.

    if the new monitor is a secondary monitor, the variants are created with
    the pids specified by the parent monitor. The fd/mmap/shm/sighand tables
    are either duplicated or attached and the new monitor is registered
    automatically.
-----------------------------------------------------------------------------*/
void monitor::init()
{
	monitor_log                    = nullptr;
	created_by_vfork               = false;
	should_shutdown                = false;
	call_succeeded                 = false;
	monitor_registered             = false;
	monitor_terminating            = false;
	monitorid                      = 0;
	parentmonitorid                = 0;
	state                          = STATE_NORMAL;
	current_signal                 = 0;
	current_signal_sent            = 0;
	current_signal_info            = nullptr;
	monitor_tid                    = 0;

	blocked_signals.resize(mvee::numvariants);
	old_blocked_signals.resize(mvee::numvariants);

	sigemptyset(&blocked_signals[0]);
	sigemptyset(&old_blocked_signals[0]);

	variants.resize(mvee::numvariants);

	monitorid                      = mvee::get_next_monitorid();
	log_init();

	pthread_mutex_init(&monitor_lock, nullptr);
	pthread_cond_init(&monitor_cond, nullptr);

#ifdef ENABLE_ERIM_POLICY
	pkey_mprotect_count = 0;
#endif
}

monitor::monitor(monitor* parent_monitor, bool shares_fd_table, bool shares_mmap_table, bool shares_sighand_table, bool shares_tgid)
{
	init();

	parentmonitorid   = parent_monitor->monitorid;

	set_mmap_table    = shares_mmap_table ?
						parent_monitor->set_mmap_table :
						std::shared_ptr<mmap_table>(new mmap_table(*parent_monitor->set_mmap_table));

	set_sighand_table = shares_sighand_table ?
						parent_monitor->set_sighand_table :
						std::shared_ptr<sighand_table>(new sighand_table(*parent_monitor->set_sighand_table));

	init_variant(parent_monitor->variants[0].pendingpid,
				 shares_tgid ? parent_monitor->variants[0].varianttgid :
				 parent_monitor->variants[0].pendingpid);

	this->variants[0].syscall_jump               = parent_monitor->variants[0].syscall_jump;
	this->variants[0].get_pku_domain_jump        = parent_monitor->variants[0].get_pku_domain_jump;
	this->variants[0].special_page               = parent_monitor->variants[0].special_page;
	this->variants[0].first_syscall_after_execve = parent_monitor->variants[0].first_syscall_after_execve;
#ifdef MVEE_CERBERUS_CP_PKU_SANDBOX_ENABLED
	/* the Hardware Breakpoints are inherited from the parent monitor */

	// we also need to reset the Hardware Breakpoints that are inherited from the parent
	for (int j = 0; j < 4; ++j) {
		this->variants[0].hw_bps[j]      = parent_monitor->variants[0].hw_bps[j];
		this->variants[0].hw_bps_type[j] = parent_monitor->variants[0].hw_bps_type[j];
	}

	// Note: This is not the right place to set the debug registers since we have not attached to it yet
#endif

	// variant monitors are a different story. New variants (forks/vforks/clones) always
	// start with a sigstop, regardless of what monitormode we run in
	state = STATE_WAITING_ATTACH;

	std::vector<pid_t> newpids = getpids();
	mvee::register_variants(newpids);
	pthread_create(&monitor_thread, nullptr, monitor::thread, this);
	debugf("Spawned variant monitor - id: %d\n", monitorid);
}

monitor::monitor(std::vector<pid_t>& pids)
{
	init();

	// the primary monitor starts with empty tables
	set_mmap_table    = std::shared_ptr<mmap_table>(new mmap_table());
	set_sighand_table = std::shared_ptr<sighand_table>(new sighand_table());

	// Monitor 0 runs in a seperate thread IF we do not run in singlethreaded mode
	// Consequently, monitor 0 starts in STATE_WAITING_ATTACH if we run in multithreaded mode
	// if we do not run in multithreaded mode, monitor 0 can start in normal mode
	state             = STATE_WAITING_ATTACH;

	init_variant(pids[0], pids[0]);

	std::vector<pid_t> newpids = getpids();
	mvee::register_variants(newpids);
	pthread_create(&monitor_thread, nullptr, monitor::thread, this);
	debugf("Spawned variant monitor - id: %d\n", monitorid);
}

// Just here so we don't instantiate an implicit destructor in MVEE.cpp
monitor::~monitor()
{
}

/*-----------------------------------------------------------------------------
    init_variant - Initializes the state info for a new variant traced by the monitor.
-----------------------------------------------------------------------------*/
void monitor::init_variant(pid_t variantpid, pid_t varianttgid)
{
	variants[0].callnum     = NO_CALL;
	variants[0].variantpid  = variantpid;
	variants[0].varianttgid = varianttgid ? varianttgid : variantpid;
	if (!mvee::config["variant"]["specs"] || !mvee::config["variant"]["specs"]["test"])
		return;
	variants[0].config      = &mvee::config["variant"]["specs"][mvee::variant_ids[0]];
}

/*-----------------------------------------------------------------------------
    rewrite_execve_args
-----------------------------------------------------------------------------*/
void monitor::rewrite_execve_args()
{
	std::string       image  = set_mmap_table->mmap_startup_info[0].image;
	std::deque<char*> argv   = get_original_argv();
	std::deque<char*> envp;
	pid_t pid = variants[0].variantpid;
	std::string lib_path_from_env;
	bool mveeroot_found_in_env = false;
	bool rewrite_envp = false;

	// See if we have any LD_LIBRARY_PATH in the envp vars
	for (auto envp : set_mmap_table->mmap_startup_info[0].envp) {
		if (envp.find("LD_LIBRARY_PATH=") == 0)
			lib_path_from_env = envp.substr(strlen("LD_LIBRARY_PATH="));
		else if (envp.find("MVEEROOT=") == 0)
			mveeroot_found_in_env = true;
	}

	// our MVEE LD Loader relies on the MVEEROOT env variable to find the
	// program interpreter. If we do not find it (e.g., in Python3), then we
	// have to inject it manually
	if (!mveeroot_found_in_env)
		rewrite_envp = true;

	// We might want to do this if we want to restart a variant altogether
	if (rewrite_envp) {
		// Get the original envp array
		char              cmd[256];
		sprintf(cmd, "strings /proc/%d/environ", variants[0].variantpid);

		std::string       envps = mvee::log_read_from_proc_pipe(cmd, nullptr);
		if (!envps.empty()) {
			std::stringstream ss(envps);
			std::string       ln;

			while(std::getline(ss, ln, '\n'))
				envp.push_back(mvee::strdup(ln.c_str()));
		}

		if (!mveeroot_found_in_env) {
			std::stringstream ss;
			ss << "MVEEROOT=" << mvee::os_get_mvee_root_dir();
			envp.push_back(mvee::strdup(ss.str().c_str()));
		}
		
		envp.push_back(nullptr);
	}

	// the original image becomes the first argument for our interpreter
	SAFEDELETEARRAY(argv.front());
	argv.pop_front();
	argv.push_front(mvee::strdup(image.c_str()));

	if (!mvee::os_add_interp_for_file(argv, image)) {
		warnf("ERROR: Could not determine interpreter for file: %s\n", image.c_str());
		shutdown(false);
		return;
	}

	// insert custom library path
	std::stringstream lib_path;
	if (!(*mvee::config_variant_exec)["library_path"].isNull()) {
		lib_path << (*mvee::config_variant_exec)["library_path"].asString();
		if (lib_path_from_env.length() > 0)
			lib_path << ":" << lib_path_from_env;
		argv.push_front(mvee::strdup(lib_path.str().c_str()));
		argv.push_front(mvee::strdup("--library-path"));
	}

	// insert ELF interpreter if necessary
	if (lib_path.str().length() > 0) {
		if (
#ifdef MVEE_ARCH_ALWAYS_USE_LD_LOADER
			true ||
#endif
			false
			)
		{
			argv.push_front(mvee::strdup(MVEE_LD_LOADER_NAME));
			image = mvee::os_get_mvee_ld_loader();
		}
		else {
			argv.push_front(mvee::strdup(MVEE_ARCH_INTERP_NAME));
			image = mvee::os_get_interp();
		}
	}

	// Everything is set up and ready to write...
#ifndef MVEE_BENCHMARK
	std::stringstream full_serialized_argv;
	for (auto arg : argv)
		if (arg)
			full_serialized_argv << arg << " ";
	debugf("%s - Injecting the following execve args - image: %s - argv: %s\n",
		   call_get_variant_pidstr().c_str(),
		   image.c_str(),
		   full_serialized_argv.str().c_str());
#endif

	// serialize, relocate, write, ...
	unsigned long argv_len = 0, envp_len = 0;

	for (unsigned i = 0; i < argv.size(); ++i)
		if (argv[i])
			argv_len += strlen(argv[i]) + 1;
	for (unsigned i = 0; i < envp.size(); ++i)
		if (envp[i])
			envp_len += strlen(envp[i]) + 1;

	char*             serialized_argv               = new char[argv_len];
	char*             serialized_envp               = (envp_len > 0) ? new char[envp_len] : nullptr;
	char**            relocated_argv                = nullptr;
	char**            relocated_envp                = nullptr;

	// Find an appropriate location to write all of this stuff
	unsigned long     total_len                     =
		(image.length() + 1) +                      // the new execve image
		(sizeof(char*) * argv.size()) +             // the argv pointer array
		(sizeof(char*) * envp.size()) +             // the envp pointer array
		argv_len +
		envp_len;

	unsigned long image_target_address;
	image_target_address = SP_IN_REGS(variants[0].regs) - 1024 - total_len;

	// now serialize and relocate
	// We want the following layout in the writable region
	// +------------------+---------------+---------------+--------------+--------------+
	// | new execve image | argv pointers | envp pointers | argv strings | envp strings |
	// +------------------+---------------+---------------+--------------+--------------+
	//
	unsigned long     relocated_argv_target_address = image_target_address + image.length() + 1;
	unsigned long     relocated_envp_target_address = relocated_argv_target_address + (sizeof(char*) * argv.size());
	unsigned long     argv_target_address           = relocated_envp_target_address + (sizeof(char*) * envp.size());
	unsigned long     envp_target_address           = argv_target_address + argv_len;

	serialize_and_relocate_arr(argv, serialized_argv, relocated_argv, argv_target_address);
	if (rewrite_envp)
		serialize_and_relocate_arr(envp, serialized_envp, relocated_envp, envp_target_address);

	debugf("%s - Writing new execve arguments...\n", call_get_variant_pidstr().c_str());
	if (rw::copy_data(mvee::os_gettid(), (void*)image.c_str(), pid, (void*)image_target_address, image.length() + 1) == -1
		|| rw::copy_data(mvee::os_gettid(), (void*)relocated_argv, pid, (void*)relocated_argv_target_address, sizeof(char*) * argv.size()) == -1
		|| (rewrite_envp && rw::copy_data(mvee::os_gettid(), (void*)relocated_envp, pid, (void*)relocated_envp_target_address, sizeof(char*) * envp.size()) == -1)
		|| rw::copy_data(mvee::os_gettid(), (void*)serialized_argv, pid, (void*)argv_target_address, argv_len) == -1
		|| (rewrite_envp && rw::copy_data(mvee::os_gettid(), (void*)serialized_envp, pid, (void*)envp_target_address, envp_len) == -1))
	{
		throw RwMemFailure(0, "execve arguments copy");
	}

	// set the registers
	debugf("%s - Setting execve registers...\n", call_get_variant_pidstr().c_str());
	ARG1(0) = image_target_address;
	ARG2(0) = relocated_argv_target_address;
	if (rewrite_envp)
		ARG3(0) = relocated_envp_target_address;
	SYSCALL_NO(0) = __NR_execve;

	if (!interaction::write_all_regs(variants[0].variantpid, &variants[0].regs))
		throw RwRegsFailure(0, "execve arguments rewrite");

	SAFEDELETEARRAY(serialized_argv);
	SAFEDELETEARRAY(serialized_envp);
	SAFEDELETEARRAY(relocated_argv);
	SAFEDELETEARRAY(relocated_envp);
 	for (unsigned i = 0; i < argv.size(); ++i)
		SAFEDELETEARRAY(argv[i]);
	for (unsigned i = 0; i < envp.size(); ++i)
		SAFEDELETEARRAY(envp[i]);
}

/*-----------------------------------------------------------------------------
  is_program_multithreaded -
-----------------------------------------------------------------------------*/
bool monitor::is_program_multithreaded()
{
	// if noone else shares the address space, the variants are either
	// single threaded or multi-threaded without the possibility to communicate
	// with other threads. In either case, it is safe to assume that we're
	// now single threaded...
	if (set_mmap_table.use_count() == 1)
		return false;

	return true;
}

/*-----------------------------------------------------------------------------
    await_pending_transfers - Used to stall the termination of a monitor until
	all of the variants that originally spawned under its supervision have been
	attached to a new monitor	
-----------------------------------------------------------------------------*/
void monitor::await_pending_transfers()
{
	interaction::mvee_wait_status status{};

	// There's an interesting race that can happen here. If we shut down just
	// after our variants have cloned but the new monitor isn't detached to the
	// new clones yet, the new monitor might get -EPERM on the attach request
	while (!mvee::shutdown_signal) {
		if (!mvee::have_detached_variants(this))
			break;
		// we might still have to detach from them...
		if (interaction::wait(-1, status, true, true) && status.reason != STOP_NOTSTOPPED)
			handle_event(status);
	}
}

/*-----------------------------------------------------------------------------
    signal_shutdown - can be called from outside this monitor's thread
    to force the monitor to shut down
-----------------------------------------------------------------------------*/
void monitor::signal_shutdown()
{
	MutexLock lock(&monitor_lock);

	// signal monitor for shutdown
	if (!should_shutdown)
		should_shutdown = true;

	warnf("signalling monitor %d for shutdown - monitor state is: %s\n", monitorid, getTextualState(state));

	pthread_cond_signal(&monitor_cond);

	if (monitor_tid) {
		long result = syscall(__NR_tgkill, mvee::os_getpid(), monitor_tid, SIGUSR1);
		if (result)
			warnf("tried to signal monitor %d for shutdown but tgkill failed: %s\n", monitorid, getTextualErrno(errno));
	}
}

/*-----------------------------------------------------------------------------
    signal_registration - signals the monitor thread when the registration
    is complete
-----------------------------------------------------------------------------*/
void monitor::signal_registration()
{
	MutexLock lock(&monitor_lock);
	monitor_registered = true;
	pthread_cond_signal(&monitor_cond);
}

/*-----------------------------------------------------------------------------
    getpids -
-----------------------------------------------------------------------------*/
std::vector<pid_t> monitor::getpids()
{
	std::vector<pid_t> result(mvee::numvariants);
	result[0] = variants[0].variantpid;
	return result;
}

/*-----------------------------------------------------------------------------
    join_thread - called by the MVEE garbage collector
-----------------------------------------------------------------------------*/
void monitor::join_thread()
{
	pthread_join(monitor_thread, nullptr);
}

/*-----------------------------------------------------------------------------
    get_mastertgid
-----------------------------------------------------------------------------*/
pid_t monitor::get_mastertgid()
{
	return variants[0].varianttgid;
}

/*-----------------------------------------------------------------------------
    mvee_mon_return - Called by each monitor thread just before returning
-----------------------------------------------------------------------------*/
void monitor::shutdown(bool success)
{
	bool have_running_variants = false;

	debugf("monitor returning - success: %d\n", success);
	if (!success)
		debugf("> errno: %d (%s)\n", errno, getTextualErrno(errno));

	if (monitor_terminating)
		return;

	monitor_terminating = true;

	// see if we can control the damage
	if (!success) {
		if (set_mmap_table)
			set_mmap_table->grab_lock();

		// if we have other monitors that monitor different processes,
		// then just kill this local process
		// and let the other monitors continue
		bool have_other_processes = mvee::is_multiprocess();

		if (!have_other_processes) {
			debugf("Cerberus is only monitoring one process group => we're shutting everything down\n");
		}
		else {
			// just kill this group
			debugf("Cerberus is monitoring multiple process groups => we're only shutting this group down\n");
			debugf("set_mmap_table->thread_group_shutting_down = %d\n", set_mmap_table->thread_group_shutting_down.load());

			if (!variants[0].variant_terminated) {
				variants[0].variant_terminated = true;
				kill(variants[0].varianttgid, SIGKILL);
			}

			if (set_mmap_table)
				set_mmap_table->release_lock();
		}
	}

	// this is hacky... haven't found a proper solution for this yet
	// we allow monitors to shut down at any point during their execution
	// even if they're holding locks...
	set_sighand_table->full_release_lock();
	set_mmap_table->full_release_lock();
	// if we're the second to last one holding a ref to this mmap table then let
	// the main thread know that we're possible singlethreaded again
	if (set_mmap_table.use_count() == 2)
		mvee::set_should_check_multithread_state(set_mmap_table->mmap_execve_id);
	// must be freed AFTER the shm table
	set_mmap_table.reset();
	set_sighand_table.reset();

	pthread_mutex_lock(&monitor_lock);
	local_detachlist.clear();
	pthread_mutex_unlock(&monitor_lock);

	if (!variants[0].variant_terminated)
		have_running_variants = true;

	if (variants[0].perf_out.length() > 0) {
		warnf("%s - Performance Counters:\n>>> START <<<\n%s\n>>> END <<<\n",
			  call_get_variant_pidstr().c_str(), variants[0].perf_out.c_str());
	}
	variants[0].perf_out.erase();

	// Successful return. Unregister the monitor from all mappings
	log_fini();
	mvee::unregister_monitor(this, !have_running_variants);

	// As soon as we shut this thread down, the remaining tracees will be able
	// to run uncontrolled => simply pause and wait for the management thread to
	// shut us down if we still have running variants
	if (!have_running_variants) {
		pthread_exit(nullptr);
	}
	else {
		pthread_mutex_lock(&monitor_lock);        
		if (!should_shutdown)
			pthread_cond_wait(&monitor_cond, &monitor_lock);
		pthread_mutex_unlock(&monitor_lock);

		// Kill off the variant now
		if (!variants[0].variant_terminated)
			kill(variants[0].variantpid, SIGKILL);

		// now move it to the dead monitors list
		mvee::unregister_monitor(this, true);
		pthread_exit(nullptr);
	}

	return;
}

/*-----------------------------------------------------------------------------
    get_original_argv - 
-----------------------------------------------------------------------------*/
std::deque<char*> monitor::get_original_argv()
{
	std::deque<char*> argv;

 	for (unsigned i = 0; i < set_mmap_table->mmap_startup_info[0].argv.size(); ++i)
		argv.push_back(mvee::strdup(set_mmap_table->mmap_startup_info[0].argv[i].c_str()));

	argv.push_back(nullptr);
	return argv;
}

/*-----------------------------------------------------------------------------
    serialize_and_relocate_arr - We can use this function to build
    a char array (e.g. argv or envp) that we will the write into a variant's
    address space at target_address.

    The function first serializes the array and then builds a pointer array
    with each pointer pointing to its corresponding element as if the serialized
    array had already been written into the variant's address space.
-----------------------------------------------------------------------------*/
void monitor::serialize_and_relocate_arr
(
	std::deque<char*>& arr,
	char*            & serialized,
	char**           & relocated,
	unsigned long    target_address
)
{
	unsigned int serialized_len = 0;

	if (!serialized) {
		for (unsigned i = 0; i < arr.size(); ++i)
			if (arr[i])
				serialized_len += strlen(arr[i]) + 1;
		serialized = new char[serialized_len];
	}

	if (!relocated)
		relocated = new char*[arr.size()];

	long         pos            = 0;
	for (unsigned i = 0; i < arr.size(); ++i) {
		if (arr[i]) {
			int len = strlen(arr[i]);
			memcpy(serialized + pos, arr[i], len + 1);
			relocated[i] = (char*)pos;
			pos         += len + 1;
		}
		else {
			relocated[i] = (char*)nullptr;
		}
	}

	for (unsigned i = 0; i < arr.size(); ++i){
		if (relocated[i] || (i == 0)) {
			relocated[i] = (char*)(target_address + (unsigned long)relocated[i]);
		}
	}
}

/*-----------------------------------------------------------------------------
    mvee_mon_handle_event - Every event we get from waitpid goes through this
    function
-----------------------------------------------------------------------------*/
void monitor::handle_event(interaction::mvee_wait_status& status)
{
	// we intercepted an event that shouldn't be delivered to this monitor
	// perhaps this is a newly spawned variant that we haven't detached from yet?
	if (variants[0].variantpid != status.pid) {
		for (auto it = local_detachlist.begin(); it != local_detachlist.end(); ++it) {
			if ((*it) == status.pid) {
				local_detachlist.erase(it);
				handle_detach_event(status.pid);
				return;
			}
		}

		debugf("Unknown variant event: %d - %s\n", status.pid, getTextualMVEEWaitStatus(status).c_str());
		unknown_variants.push_back(status.pid);
		return;
	}

	// check for exit events first
	if (unlikely(status.reason == STOP_EXIT)) {
		handle_exit_event();
		return;
	}
	else if (status.reason == STOP_SYSCALL) {
		handle_syscall_event();
		return;
	}
	else if (status.reason == STOP_FORK) {
		handle_fork_event(status);
		return;
	}
	else if (status.reason == STOP_SIGNAL) {
		if (status.data == SIGTRAP) {
			handle_trap_event();
		}
		else if (status.data == SIGSEGV) {
#ifdef MVEE_CERBERUS_CP_PKU_SANDBOX_ENABLED
			call_grab_locks(MVEE_SYSLOCK_MMAN);

			siginfo_t siginfo;
			if (interaction::get_signal_info(variants[0].variantpid, &siginfo)) {
				/* TODO race conditions may happen in case that we have multiple threads changing permissions and mapping code
				 * This could lead to attacks similar to the ones described in PKU Pitfalls paper and/or monitor state.
				 *
				 * 1) Need to put correct locks (similar to mprotect, mmap, munmap etc)
				 * 2) Stop world in multi-threading apps and update hw bps in all threads (difficult)
				 * 3) Check call handlers of mmap, mprotect etc. for comments
				 */

				void* sigsegv_page_addr = (PAGE_OF_ADDRESS(siginfo.si_addr));
				// check if SIGSEGV was triggered from a page with "changed" permissions that has dangerous instructions
				if (set_mmap_table->prot_non_exec_map.find((unsigned long)sigsegv_page_addr) != set_mmap_table->prot_non_exec_map.end()) {
#ifdef CHECK_IF_INSTRUCTION_EMULATIONS_IS_NEEDED
					warnf("Need to intergrade the emulation engine here\n");
#endif
					// if we have another active page with dangerous instructions we need to do some additional work
					if (set_mmap_table->active_executable_page_with_dangerous_instructions) {
						// make the current active_executable_page_with_dangerous_instructions non-executable (but remains readable)
						if (postcall_set_page_prot_non_exec(set_mmap_table->active_executable_page_with_dangerous_instructions, true) != 0)
							warnf("Failed to change permissions of page %p\n", (void*)set_mmap_table->active_executable_page_with_dangerous_instructions);
						// clear all dangerous instructions (all of them are in the active_executable_page_with_dangerous_instructions)
						set_mmap_table->active_dangerous_instructions.clear();
						// take back the debug registers
						clear_all_watches();
					}

					// scan memory of that page, get dangerous instructions and add them to the active dangerous instructions
					set_mmap_table->active_dangerous_instructions = monitor::pmparser_get_dangerous_instructions(sigsegv_page_addr, PAGE_SIZE, true, ONLY_NON_EXEC);

					// deal with partial dangerous instructions
					auto partial_dangerous_instructions = pmparser_get_partial_dangerous_instructions(sigsegv_page_addr, PAGE_SIZE, ONLY_NON_EXEC, ONLY_EXEC);
					for (const auto& partial_dangerous_instruction: partial_dangerous_instructions) {
						// if there is a partial dangerous instruction in the previous page we should make it non-executable
						if (PAGE_OF_ADDRESS(partial_dangerous_instruction.first) != sigsegv_page_addr) {
							if (postcall_set_page_prot_non_exec((unsigned long)PAGE_OF_ADDRESS(partial_dangerous_instruction.first), true) != 0)
								warnf("Failed to change permissions of page %p\n", PAGE_OF_ADDRESS(partial_dangerous_instruction.first));
						}
						// otherwise just add the partial dangerous instruction to the active dangerous instructions
						else {
							set_mmap_table->active_dangerous_instructions.insert(std::make_pair(partial_dangerous_instruction.first, partial_dangerous_instruction.second));
						}
					}

					// we do not support this case yet TODO (single stepping)
					if (set_mmap_table->active_dangerous_instructions.size() > 4) {
						warnf("We mapped as executable a page with more than 4 dangerous instructions. This case is not supported by our implementation!!!\n");
						warnf("You Shall Not byPass my PKU-based Sandbox: Not supported use case.\n");
						shutdown(false);
						call_release_locks(MVEE_SYSLOCK_MMAN);
						return;
					}
					// set hardware breakpoints in the active_executable_page_with_dangerous_instructions
					else {
						for (const auto& dangerous_instruction: set_mmap_table->active_dangerous_instructions) {
							if (!hwbp_set_watch(dangerous_instruction.first, dangerous_instruction.second ? MVEE_BP_EXEC_ONLY_XRSTOR : MVEE_BP_EXEC_ONLY))
								warnf("%s Failed to set hw bp: 0x" PTRSTR "\n", call_get_variant_pidstr().c_str(), dangerous_instruction.first);
						}
					}

					// make executable the page in which the SIGSEGV was triggered
					if (postcall_set_page_prot_non_exec((unsigned long)sigsegv_page_addr, false) != 0)
						warnf("Failed to change permissions of page %p\n", PAGE_OF_ADDRESS(sigsegv_page_addr));

					if (set_mmap_table->prot_non_exec_map.empty()) {
						debugf("Some dangerous instructions were deleted ... using ONLY hardware breakpoints is enough for the moment\n");
						set_mmap_table->active_executable_page_with_dangerous_instructions = 0;
					}
					else {
						set_mmap_table->active_executable_page_with_dangerous_instructions = (unsigned long)sigsegv_page_addr;
					}

					call_release_locks(MVEE_SYSLOCK_MMAN);
					call_resume();
					return;
				}
			}

			call_release_locks(MVEE_SYSLOCK_MMAN);
#endif
		}
		else if (status.data == SIGSTOP) {
			if (state == STATE_WAITING_ATTACH && !variants[0].variant_attached) {
				handle_attach_event();
				return;
			}
			if (state == STATE_WAITING_RESUME && !variants[0].variant_resumed) {
				handle_resume_event();
				return;
			}
		}
	}
	else if (status.reason == STOP_EXECVE) {
		call_resume();
		return;
	}
#ifdef MVEE_CERBERUS_CP_PKU_SANDBOX_ENABLED
	// dealing with Hardware Breakpoints
	else if (status.reason == STOP_NOTSTOPPED) {
		// handle_hw_bp_event_v1(status);
		handle_hw_bp_event_v2(status);
		return;
	}
#endif

	handle_signal_event(status);
}

/*-----------------------------------------------------------------------------
    handle_attach_event
-----------------------------------------------------------------------------*/
void monitor::handle_attach_event()
{
	variants[0].variant_attached = true;
	if (!interaction::attach(variants[0].variantpid))
		throw AttachFailure(0);

	debugf("%s - Attached to variant\n", call_get_variant_pidstr().c_str());

	if (variants[0].variant_attached)
		state = STATE_WAITING_RESUME;
}

/*-----------------------------------------------------------------------------
    handle_detach_event - this variant was created by our monitor
    but we shouldn't be tracing it
-----------------------------------------------------------------------------*/
void monitor::handle_detach_event(pid_t variantpid)
{
	detachedvariant* new_variant = nullptr;

	debugf("received event for variant: %d\n", variantpid);

	// look for the variant in the global detach list
	new_variant = mvee::remove_detached_variant(variantpid);

	if (!new_variant) {
		warnf("couldn't find detached variant: %d in detachlist!\n", variantpid);
		shutdown(false);
		return;
	}

	if (!new_variant->transfer_func) {
		warnf("It seems that you are trying to run a multi-threaded or multi-process application.\n");
		warnf("For these applications, Cerberus currently injects a small infinite loop to\n");
		warnf("which we transfer the control while detaching a monitor from a variant\n");
		warnf("thread. By the time the new monitor attaches to this thread, the thread\n");
		warnf("will still be in this infinite loop (duh).\n");
		warnf("\n");
		warnf("Without this trick we'd have to wait until the first syscall in order to\n");
		warnf("safely detach from a thread.\n");
		warnf("\n");
		warnf("Seems that the infinite loop was not injected correctly\n");
		shutdown(false);
		return;
	}

	if (!interaction::read_all_regs(new_variant->variantpid, &new_variant->original_regs))
		throw RwRegsFailure(-new_variant->variantpid, "pre-detach read");

	PTRACE_REGS tmp{};
	memcpy(&tmp, &new_variant->original_regs, sizeof(PTRACE_REGS));
	// instruct the variant to execute the transfer func
	IP_IN_REGS(tmp) = (unsigned long)new_variant->transfer_func;

	if (!interaction::write_all_regs(new_variant->variantpid, &tmp))
		throw RwRegsFailure(-new_variant->variantpid, "pre-detach write");

	if (!interaction::detach(new_variant->variantpid))
		throw DetachFailure(-new_variant->variantpid, "pre-transfer");

	debugf("Detached from variant (PID: %d) => set ip to: " PTRSTR "\n", new_variant->variantpid, new_variant->transfer_func);

	new_variant->parent_has_detached = 1;
	monitor*       new_mon = new_variant->new_monitor;

	mvee::add_detached_variant(new_variant);

	// we can now register the new monitor
	if (mvee::have_pending_variants(new_mon) == mvee::numvariants) {
		debugf("Detached from all variants in this thread set!\n");

		// make sure that the pids don't stick around in the local detachlist
		int reset_it = 1;
		while (reset_it) {
			reset_it = 0;
			for (auto it = local_detachlist.begin(); it != local_detachlist.end(); ++it) {
					if (*it == new_mon->variants[0].variantpid) {
						local_detachlist.erase(it);
						reset_it = 1;
						break;
					}

				if (reset_it)
					break;
			}
		}

		mvee::register_monitor(new_mon);
	}
}

/*-----------------------------------------------------------------------------
    handle_resume_event
-----------------------------------------------------------------------------*/
void monitor::handle_resume_event()
{
	variants[0].variant_resumed = true;
	if (!interaction::setoptions(variants[0].variantpid))
		throw RwInfoFailure(0, "post-attach");

	// before we resume the variant, we have to look for it in the global detachlist
	if (monitorid) {
		detachedvariant* attached_variant = mvee::remove_detached_variant(variants[0].variantpid);

		if (!attached_variant) {
			warnf("attached to a variant that did not appear in the detachlist - FIXME!\n");
			shutdown(false);
			return;
		}

		variants[0].infinite_loop_ptr = attached_variant->transfer_func;
		variants[0].tid_address[0]    = attached_variant->tid_address[0];
		variants[0].tid_address[1]    = attached_variant->tid_address[1];

		if (!interaction::write_all_regs(variants[0].variantpid, &attached_variant->original_regs))
			throw RwRegsFailure(0, "post-attach");

		delete attached_variant;
	}
	else {
		if (!rw::write_primitive<unsigned long>(variants[0].variantpid, (void*) &mvee::can_run, 1)) {
			warnf("%s - Couldn't resume variant\n", call_get_variant_pidstr().c_str());
			exit(-1);
			return;
		}
	}

#ifdef MVEE_CERBERUS_CP_PKU_SANDBOX_ENABLED
	// This is the right place to set the debug registers after a fork.
	// Hardware breakpoints seem to be cleared either due to the fork or
	// due to the fact that the monitor detached. So we reset them!!!
	hwbp_refresh_regs();
#endif

#ifdef MVEE_CERBERUS_KERNEL_PKU_SANDBOX_ENABLED
	// after a fork-like system call we need to reinitialize the sensitive inode of Cerberus
	if (variants[0].syscall_jump)
		postcall_init_cerberus_kernel_pku_sandbox();
#endif

	debugf("%s - resumed variant\n", call_get_variant_pidstr().c_str());
	call_resume();
	state = STATE_NORMAL;
}

/*-----------------------------------------------------------------------------
    handle_exit_event
-----------------------------------------------------------------------------*/
void monitor::handle_exit_event()
{
	debugf("%s - received SIGTERM\n", call_get_variant_pidstr().c_str());

	// we treat this as an entrance to a sys_exit call so
	// we can detect divergences where one variant is shut down
	// while others are still trying to execute lockstepped calls
	variants[0].variant_terminated = true;
	variants[0].callnum          = __NR_exit;
	variants[0].call_type        = MVEE_CALL_TYPE_NORMAL;

	debugf("Variant process has terminated. Shutting down.\n");
	shutdown(true);
}

/*-----------------------------------------------------------------------------
    handle_fork_event
-----------------------------------------------------------------------------*/
void monitor::handle_fork_event(interaction::mvee_wait_status& status)
{
	// Store new pid in variantstate
	variants[0].pendingpid = (int) status.data;

	debugf("%s - Fork Event- Pending PID: %d\n", call_get_variant_pidstr().c_str(), variants[0].pendingpid);

	bool      bSpawnMonitor = true;
	if (variants[0].pendingpid == 0)
		bSpawnMonitor = false;

	if (bSpawnMonitor) {
		bool     shares_fd_table      = false;
		bool     shares_mmap_table    = false;
		bool     shares_sighand_table = false;
		bool     shares_threadgroup   = false;

		if (variants[0].callnum == __NR_clone) {
			shares_fd_table      = ARG1(0) & CLONE_FILES;
			shares_mmap_table    = ARG1(0) & CLONE_VM;
			shares_sighand_table = ARG1(0) & CLONE_SIGHAND;
			shares_threadgroup   = ARG1(0) & CLONE_THREAD;
		}
		else if (variants[0].callnum == __NR_vfork) {
			// variants created by vfork share an address space with their parent
			// until they call execve
			shares_mmap_table = true;
		}

		auto new_monitor = new monitor(this, shares_fd_table, shares_mmap_table, shares_sighand_table, shares_threadgroup);
		if (variants[0].callnum == __NR_vfork)
			new_monitor->created_by_vfork = true;

		auto new_variant = new detachedvariant;
		memset(new_variant, 0, sizeof(detachedvariant));

		// init detachedvariant
		new_variant->variantpid          = variants[0].pendingpid;
		variants[0].pendingpid           = 0;
		new_variant->parentmonitorid     = monitorid;
		new_variant->parent_has_detached = 0;
		new_variant->transfer_func       = variants[0].infinite_loop_ptr;
		new_variant->new_monitor         = new_monitor;

		if (variants[0].callnum == __NR_clone) {
			if (ARG1(0) & CLONE_PARENT_SETTID)
				new_variant->tid_address[0] = (void*)ARG3(0);
			if (ARG1(0) & CLONE_CHILD_SETTID)
				new_variant->tid_address[1] = (void*)ARG4(0);
		}

		// register in global detachlist so the new monitor can see it
		mvee::add_detached_variant(new_variant);

		// register in the local detachlist so we can recognize the detach event
		local_detachlist.push_back(new_variant->variantpid);

		// look for variants we've already received an event from
		for (auto it = unknown_variants.begin(); it != unknown_variants.end(); ++it) {
			if (*it == new_variant->variantpid) {
				handle_detach_event(new_variant->variantpid);
				unknown_variants.erase(it);
				break;
			}
		}

		call_resume();
		state = STATE_IN_SYSCALL;
	}
}

/*-----------------------------------------------------------------------------
    handle_trap_event
-----------------------------------------------------------------------------*/
void monitor::handle_trap_event()
{
	warnf("Should we come inside handle_trap_event? (Maybe need TODO something here to treat this)\n");

	// not a known event. Might be a breakpoint!
	siginfo_t siginfo;
	if (interaction::get_signal_info(variants[0].variantpid, &siginfo) && siginfo.si_code == MVEE_TRAP_HWBKPT)
		log_hw_bp_event();

	call_resume();
}

/*-----------------------------------------------------------------------------
    handle_syscall_entrance_event
-----------------------------------------------------------------------------*/
void monitor::handle_syscall_entrance_event()
{
	long  precall_flags, call_flags;
	variants[0].regs_valid          = false;
	call_check_regs();

	long  callnum = SYSCALL_NO(0);

	// call GET_CALL_TYPE handler (if present)
	variants[0].callnum         = callnum;
	variants[0].call_type       = call_precall_get_call_type(variants[0].callnum);

	if (variants[0].first_syscall_after_execve) {
		variants[0].first_syscall_after_execve = false;

#ifdef MOVE_LOADER_FUNCTIONALITY_IN_MONITOR
 #ifdef MVEE_CERBERUS_KERNEL_PKU_SANDBOX_ENABLED
		precall_init_cerberus();
 #endif
		// set infinite loop
		precall_set_infinite_loop();
		// set jumps and special page
		precall_set_jumps_and_special_page();
#endif
	}

#ifndef MVEE_BENCHMARK
	// call LOG_ARGS handler (if present
	call_precall_log_args(variants[0].callnum);
#endif

	// the current syscall is unsynced. dispatch it!
	if (variants[0].call_type == MVEE_CALL_TYPE_UNSYNCED) {
		debugf("%s - >>> Dispatch as UNSYNCED NORMAL\n", mvee::upcase(getTextualSyscall(variants[0].callnum)).c_str());

		// call CALL handler (if present)
		variants[0].call_flags  = call_call_dispatch_unsynced();
		if (variants[0].call_flags & MVEE_CALL_DENY)
			call_resume_fake_syscall();
		else
			call_resume();
		return;
	}

	// All variants have reached the sync point
	if (sig_prepare_delivery())
		return;

	// Call PRECALL handler (if present)
	precall_flags = call_precall();

	// Arguments match => let's see how this call should be dispatched
	if (precall_flags & MVEE_PRECALL_ARGS_MATCH) {
		if (precall_flags & MVEE_PRECALL_CALL_DISPATCH_NORMAL) {
			debugf("%s - >>> Dispatch as SYNCED NORMAL\n", mvee::upcase(getTextualSyscall(variants[0].callnum)).c_str());
			state = STATE_IN_SYSCALL;
		}
		else if (precall_flags & MVEE_PRECALL_CALL_DISPATCH_FORK) {
			debugf("%s - >>> Dispatch as SYNCED FORKCALL\n", mvee::upcase(getTextualSyscall(variants[0].callnum)).c_str());
			state = STATE_IN_FORKCALL;
		}
		else if (precall_flags & MVEE_PRECALL_CALL_DENY) {
			// dispatch denied in PRECALL handler
			// This usually indicates a mismatch
			debugf("%s - >>> Dispatch DENIED - Shutting down monitor\n",
				   mvee::upcase(getTextualSyscall(variants[0].callnum)).c_str());
			shutdown(false);
			return;
		}

		// Call CALL handler (if present)
		call_flags = call_call_dispatch();

		variants[0].call_flags      = call_flags;

		if (call_flags & MVEE_CALL_DENY) {
			call_resume_fake_syscall();
			return;
		}

		call_resume();
		return;
	}
		// Arguments do not match
		// We should never come here in Cerberus
	else {
		warnf("Arguments should never mismatch in Cerberus ... something is really wrong.\n");
		shutdown(false);
	}
}

/*-----------------------------------------------------------------------------
    handle_syscall_exit_event
-----------------------------------------------------------------------------*/
void monitor::handle_syscall_exit_event()
{
	variants[0].return_valid = false;
	call_postcall_get_variant_result();

	// Whether we decide to deliver the signal right away or not, we still have
	// to restart the syscall!
	if (variants[0].return_value == -ERESTARTNOHAND
		|| variants[0].return_value == -ERESTARTSYS
		|| variants[0].return_value == -ERESTART_RESTARTBLOCK
		|| variants[0].return_value == -ERESTARTNOINTR)
	{
		if (in_signal_handler() && variants[0].return_value == -ERESTARTNOHAND) {
			debugf("%s - >>> JUMPING TO SIGNAL HANDLER\n", call_get_variant_pidstr().c_str());
			variants[0].callnum = NO_CALL;
			state               = STATE_NORMAL;
			call_resume();
			return;
		}

		sig_restart_syscall();
		return;
	}

	variants[0].prevcallnum       = variants[0].callnum;
	variants[0].callnum           = NO_CALL;
	variants[0].restarted_syscall = false;

	// if the last syscall we've entered was an unsynced call
	// then dispatch the return right away...
	if (variants[0].call_type == MVEE_CALL_TYPE_UNSYNCED) {
		if (variants[0].call_flags & MVEE_CALL_DENY) {
			// Write the return value determined by the CALL handler
			call_write_denied_syscall_return();
		}
		else {
			call_succeeded = call_check_result(variants[0].return_value);
			// Call POSTCALL and LOG_RETURN handlers (if present)
			call_postcall_log_return();
			call_postcall_return_unsynced();
		}

		if (variants[0].have_overwritten_args)
			call_restore_args();

		call_resume();
		variants[0].call_type = MVEE_CALL_TYPE_UNKNOWN;
		return;
	}

	// Sync point reached... It's safe to let the variant return now
	if (in_signal_handler() && !current_signal_sent) {
		debugf("The variant has returned and we can now deliver the signal.\n");
		sig_finish_delivery();
		return;
	}

	if (variants[0].call_flags & MVEE_CALL_DENY) {
		call_write_denied_syscall_return();
		state = STATE_NORMAL;
		if (variants[0].have_overwritten_args)
			call_restore_args();
		call_resume();
		return;
	}

	call_succeeded = call_check_result(call_postcall_get_variant_result());
	call_postcall_log_return();

	long resume_flags = call_postcall_return();

	state = STATE_NORMAL;

	if (resume_flags != MVEE_POSTCALL_DONTRESUME) {
		if (variants[0].have_overwritten_args)
			call_restore_args();
		call_resume();
	}
	else {
		debugf("WARNING: postcall handler handled resume. not resuming...\n");
	}
}

/*-----------------------------------------------------------------------------
    handle_syscall_event
-----------------------------------------------------------------------------*/
void monitor::handle_syscall_event()
{
	// ERESTARTSYS handler
	if (variants[0].restarting_syscall && !variants[0].restarted_syscall) {
		debugf("%s - restarted syscall is back at syscall entry\n", call_get_variant_pidstr().c_str());
		if (variants[0].call_type != MVEE_CALL_TYPE_UNSYNCED && state != STATE_IN_FORKCALL) {
			variants[0].restarted_syscall = true;

			// Do not blindly resume the variant here! If it's a normal call
			// that was restarted in the variant, we still have
			// to check if we can maybe deliver that pending signal.
			debugf("The variant was restarted and is now back at the syscall entry\n");
			if (sig_prepare_delivery()) {
				// debugf("Signal delivery in progress!\n");
				variants[0].restarting_syscall = false;
			}
			else {
				// no signal to be delivered. Was this a spurious wakeup?!
				debugf("no signal to be delivered...\n");
				debugf("%s - all restarted - resuming variant from restarted syscall entry\n", call_get_variant_pidstr().c_str());
				variants[0].restarting_syscall = variants[0].restarted_syscall = false;
				call_resume();
			}

			return;
		}
		else {
			debugf("%s - unsynced or forkcall - resuming variant from restarted syscall entry\n", call_get_variant_pidstr().c_str());
			variants[0].restarting_syscall = variants[0].restarted_syscall = false;
			call_resume();
		}

		return;
	}

	if (variants[0].callnum == NO_CALL)
		handle_syscall_entrance_event();
	else
		handle_syscall_exit_event();
}

/*-----------------------------------------------------------------------------
    handle_signal_event - Handles a signal sent to a variant.

    We execute this whenever a signal interrupts the execution of the variant.
    For asynchronous signals, we'll first call this when the initial signal
    is sent. We will then usually discard that signal and wait for a sync
    point. Then, at the sync point, we send the original signal ourselves
    and we let it go through from within this function.
-----------------------------------------------------------------------------*/
void monitor::handle_signal_event(interaction::mvee_wait_status& status)
{
	siginfo_t siginfo;
	unsigned long ret;

	// Terminated by unhandled signal
	if (status.reason == STOP_KILLED) {
	variants[0].variant_terminated = true;
		if (!is_group_shutting_down()) {
			warnf("%s - terminated by an unhandled %s signal.\n",
				  call_get_variant_pidstr().c_str(),
				  getTextualSig(status.data));
		}

		// Since we cannot recover from this, we might as well shut
		// down the variants that have not received the signal
		shutdown(false);
		return;
	}
	else if (status.reason == STOP_SIGNAL) { // stopped by the delivery of a signal
		int signal = status.data;
		if (signal == SIGALRM)
			debugf("%s - caught SIGALRM - should_shutdown: %d\n", call_get_variant_pidstr().c_str(), should_shutdown);

		if (!interaction::get_signal_info(variants[0].variantpid, &siginfo))
			throw RwInfoFailure(0, "get signal info");

		debugf("%s - Received signal %s (%d)\n", call_get_variant_pidstr().c_str(), getTextualSig(signal), signal);
		if (!interaction::fetch_syscall_return(variants[0].variantpid, ret))
			throw RwRegsFailure(0, "read syscall num/return at trap location");

		debugf("%s - ret is currently: %ld\n", call_get_variant_pidstr().c_str(), ret);

		if (signal == SIGSEGV || signal == SIGBUS) {
			log_segfault();

			// segfault in signal handler. Pretend like nothing happened :)))
			if (in_signal_handler()) {
				warnf("%s - A fatal signal was delivered while executing a signal handler.\n", call_get_variant_pidstr().c_str());
				warnf("%s - We're just quietly shutting down this variant set and moving on ;)\n", call_get_variant_pidstr().c_str());
				variants[0].variant_terminated = true;
				shutdown(true);
				return;
			}
		}

		if (sighand_table::is_control_flow_signal(signal)) {
			// immediately deliver signals that are probably caused by the
			// normal control flow
			debugf("%s Delivering control flow signal %s to variant.\n", call_get_variant_pidstr().c_str(), getTextualSig(signal));

			if (set_sighand_table->will_cause_termination(signal))
				set_mmap_table->thread_group_shutting_down = true;

			// deliver control flow signal
			if (!interaction::resume_until_syscall(variants[0].variantpid, signal))
				throw ResumeFailure(0, "resume after signal injection");
		}
		// if the MVEE is injecting the signal, then the monitor
		// will be the sender in siginfo.si_pid
		else if (siginfo.si_pid == mvee::os_getpid()) {
			debugf("%s - signal %s is ready for injection in variant\n", call_get_variant_pidstr().c_str(), getTextualSig(signal));

			if (current_signal_info) {
				// restore the original sender
				siginfo.si_pid  = current_signal_info->si_pid;

				if (!interaction::set_signal_info(variants[0].variantpid, &siginfo))
					throw RwInfoFailure(0, "set original signal info");
				// if we're in a restarted sigsuspend, we will see the exit
				// site of the call before the actual sighandler is invoked
				//
				// if we're in a regular sigsuspend, we will not see the exit
				// site but instead jump to the sighandler right away
				if (!variants[0].restarting_syscall && !variants[0].restarted_syscall) {
					debugf("%s - this is not a restarted call. We're expecting to see the signal handler right away!\n", call_get_variant_pidstr().c_str());
					variants[0].callnum = NO_CALL;
					state               = STATE_NORMAL;
				}

				variants[0].current_signal_ready = true;

				if (variants[0].current_signal_ready) {
					debugf("%s - signal is ready for injection in all variants. Injecting...\n",
						   call_get_variant_pidstr().c_str());
					debugf("%s - releasing syslocks for %lu (%s)\n",
						   call_get_variant_pidstr().c_str(),
						   variants[0].callnumbackup, 
						   getTextualSyscall(variants[0].callnumbackup));

					if (set_sighand_table->will_cause_termination(signal))
						set_mmap_table->thread_group_shutting_down = true;

					if (!interaction::resume_until_syscall(variants[0].variantpid, signal))
						throw ResumeFailure(0, "resume after signal injection");
				}
			}
			else {

				debugf("%s - signal NOT injected!!! Was this a shutdown signal???\n", call_get_variant_pidstr().c_str());
			}

			// Now it SHOULD be safe to release the sighand lock
			// There might still be a race (TODO: Check kernel implementation)
			// if another thread changes the signal disposition of the injected signal
			// before the current thread is effectively resumed, the signal might
			// be improperly handled
			// mvee_sig_release_lock();
		}
		else {
			bool insert_pending_sig = true;
			debugf("%s - intercepted signal %s from pid: %d\n", call_get_variant_pidstr().c_str(), getTextualSig(signal), siginfo.si_pid);
			if (signal > 0 && signal <= 32) {
				// do not store duplicates for non-real time signals
				for (auto it = pending_signals.begin();
					 it != pending_signals.end(); ++it)
				{
					if (it->sig_no == signal) {
						debugf("%s - found duplicate signal in pending list. Ignoring signal\n", call_get_variant_pidstr().c_str());

						// but we should mark a bit in the recv mask
						it->sig_recv_mask |= (1 << 0);
						insert_pending_sig = false;
						break;
					}
				}
			}

			if (insert_pending_sig) {
				mvee_pending_signal tmp{};
				tmp.sig_no           = siginfo.si_signo;
				tmp.sig_recv_mask    = (1 << 0);
				memcpy(&tmp.sig_info, &siginfo, sizeof(siginfo_t));
				pending_signals.push_back(tmp);
				debugf("%s - signal queued\n", call_get_variant_pidstr().c_str());
			}

			// Continue normal execution for now.
			// When a signal is ignored, the variant that was about to execute the sighandler
			// will execute a sys_restart_syscall call.
			call_resume();
		}
	}
	else {
		warnf("This (Hardware Breakpoint related) case is not treated yet (TODO)");
	}
}

/*-----------------------------------------------------------------------------
    handle_hw_bp_event_v2 - Handles a Hardware Breakpoint that triggered in the variant

    Currently this code works correctly under the following assumptions:
        1) up to 4 "dangerous" instructions to vet in one page

-----------------------------------------------------------------------------*/
void monitor::handle_hw_bp_event_v1(interaction::mvee_wait_status& status)
{
	siginfo_t siginfo;

	// check if it is a Hardware Breakpoint
	if (interaction::get_signal_info(variants[0].variantpid, &siginfo) && siginfo.si_code == MVEE_TRAP_HWBKPT) {
		log_hw_bp_event();
		int watch_index = get_triggered_watch();
		if (watch_index >= 0) {
			if (variants[0].hw_bps_type[watch_index] == MVEE_BP_EXEC_ONLY_XRSTOR) {
				// make sure that we get a fresh "view" on the registers
				if (!interaction::read_all_regs(variants[0].variantpid, &variants[0].regs))
					throw RwRegsFailure(0, "refresh syscall args");

				interaction::mvee_wait_status tmp_status{};

				// check if this is a safe XRSTOR
				// if it is a safe XRSTOR we can continue
				// in any other case we stop execution if a Hardware Breakpoint is hit
				if (!CHECK_BIT(variants[0].regs.rax, 9)) {
					ptrace(PTRACE_SINGLESTEP, variants[0].variantpid, nullptr, nullptr);
					interaction::wait(variants[0].variantpid, tmp_status);
					call_resume();
					return;
				}
			}
		}
		else {
			warnf("1) This case (related to Hardware Breakpoints) is not treated yet (TODO).\n");
		}

		warnf("You Shall Not byPass my PKU-based Sandbox: Attempt to Execute a Dangerous Instruction\n");

		shutdown(false);
		call_resume();
		return;
	}

	warnf("2) This case (related to Hardware Breakpoints) is not treated yet (TODO).\n");
	call_resume();
}

/*-----------------------------------------------------------------------------
    handle_hw_bp_event_v2 - Handles a Hardware Breakpoint that triggered in the variant

    Currently this code works correctly under the following assumptions:
        1) libc and libdl are rewritten and all explicit XRSTOR instructions are followed by checks
                   &
        2) any other XRSTOR instructions (not described in 1)) is considered dangerous
                   &
        3) up to 4 "dangerous" instructions to vet in one page
-----------------------------------------------------------------------------*/
void monitor::handle_hw_bp_event_v2(interaction::mvee_wait_status& status)
{
	siginfo_t siginfo;

	// check if it is a Hardware Breakpoint
	if (interaction::get_signal_info(variants[0].variantpid, &siginfo) && siginfo.si_code == MVEE_TRAP_HWBKPT) {
		log_hw_bp_event();
		int watch_index = get_triggered_watch();
		// any valid hw breakpoint points to something dangerous that should be stopped
		if (watch_index >= 0) {
			warnf("You Shall Not byPass my PKU-based Sandbox: Attempt to Execute a Dangerous Instruction\n");
			shutdown(false);
			call_resume();
			return;
		}
	}

	warnf("This case (related to Hardware Breakpoints) is not treated yet (TODO).\n");
	call_resume();
}

/*-----------------------------------------------------------------------------
    handle_dangerous_instruction - Handle detected "dangerous" instruction that could modify PKRU

    Handle the dangerous instruction detected at @address_to_vet
    If @is_deleted is true the address refers to a recently deleted instruction, otherwise it refers to a recently added instructions

    !!! This should only be called at posthandlers of system calls or maybe when we handle a signal !!!
    TODO we need more handling in case that a mapped page has more than 4 dangerous instructions (SINGLE STEPPING is one of the solutions)
-----------------------------------------------------------------------------*/
void monitor::handle_dangerous_instruction(unsigned long address_to_vet, bool is_XRSTOR, bool is_deleted)
{
	if (!is_deleted) {
		//  a) we end here if we have already done the "initial" required work to deal with more than 4 detected dangerous instructions
		//     and we have changed the permissions of that page
		//                         or
		//  b) we end here if we try to make executable a page that Cerberus already made non-executable
		//
		//  Note: there is some redundancy in this code since it will be repeated for each of the new detected dangerous instructions (but this is fine)
		if (set_mmap_table->prot_non_exec_map.find((unsigned long)(PAGE_OF_ADDRESS(address_to_vet))) != set_mmap_table->prot_non_exec_map.end()) {
			// we update bookkeeping in order to "force" change of permissions of this page (this is needed due to the way set_page_prot_non_exec works)
			set_mmap_table->prot_non_exec_map.erase((unsigned long)(PAGE_OF_ADDRESS(address_to_vet)));
			// make page with dangerous instructions non-executable but readable
			if (postcall_set_page_prot_non_exec(address_to_vet, true) != 0)
				warnf("Failed to change permissions of page %p\n", PAGE_OF_ADDRESS(address_to_vet));
			// no need to add this address to dangerous instructions
			return;
		}

		// ok it is safe to add the dangerous instructions now
		if (set_mmap_table->prot_non_exec_map.empty())
			set_mmap_table->active_dangerous_instructions.insert(std::make_pair(address_to_vet, is_XRSTOR));

		// Hardware Breakpoints are not enough
		// we just discovered a 5th dangerous instruction, we need to do some more "initial" work
		if (set_mmap_table->active_dangerous_instructions.size() == 5) {
			debugf("We detected a 5th dangerous instructions ... using ONLY hardware breakpoints is not enough for the moment\n");
			// make all pages with dangerous instructions non-executable but readable
			// there is some redundancy in this code since it will be repeated for each of the new detected dangerous instructions (but this is fine)
			for (const auto& dangerous_instruction: set_mmap_table->active_dangerous_instructions) {
				if (postcall_set_page_prot_non_exec(dangerous_instruction.first, true) != 0)
					warnf("Failed to change permissions of page %p\n", PAGE_OF_ADDRESS(dangerous_instruction.first));
			}

			// remove hardware breakpoints
			clear_all_watches();
			// remove all active dangerous instructions (none of them is active now)
			set_mmap_table->active_dangerous_instructions.clear();
		}
		// we end here if we have already done the "initial" required work to deal with more than 4 detected dangerous instructions and we have not changed the permissions of that page yet
		// there is some redundancy in this code since it will be repeated for all the new detected dangerous instructions but this is fine
		else if (!set_mmap_table->prot_non_exec_map.empty()) {
			// make non-executable the page that includes the dangerous instruction
			if (postcall_set_page_prot_non_exec(address_to_vet, true) != 0)
				warnf("Failed to change permissions of page %p\n", PAGE_OF_ADDRESS(address_to_vet));
		}
		// Hardware Breakpoints are enough ... for the moment
		else {
			if (!hwbp_set_watch(address_to_vet, is_XRSTOR ? MVEE_BP_EXEC_ONLY_XRSTOR : MVEE_BP_EXEC_ONLY))
				warnf("%s Failed to set hw bp: 0x" PTRSTR "\n", call_get_variant_pidstr().c_str(), address_to_vet);
		}
	}
	else {
		// !!! this is a corner case !!!
		// An application could munmap or make non-executable a page that was made executable by Cerberus
		// In this case then we need to update our bookkeeping
		// Note: We treat each dangerous instruction separately. If this page has more than 1 dangerous instruction
		// we "need" to do nothing for the rest of them (they go to Black Hole). Look for Black Hole comment later in this code.
		// Note2: We do not need to change permissions ourselves ... the application would munmap it or change permissions
		if ((unsigned long)(PAGE_OF_ADDRESS(address_to_vet)) == set_mmap_table->active_executable_page_with_dangerous_instructions) {
			set_mmap_table->active_executable_page_with_dangerous_instructions = 0;
			set_mmap_table->active_dangerous_instructions.clear();
			set_mmap_table->prot_non_exec_map.erase((unsigned long)(PAGE_OF_ADDRESS(address_to_vet)));
			clear_all_watches();
			return;
		}

		// we removed one of the active dangerous instructions
		if (set_mmap_table->active_dangerous_instructions.find(std::pair<unsigned long, bool>(address_to_vet, is_XRSTOR)) != set_mmap_table->active_dangerous_instructions.end()) {
			// if the application munmap or makes non-executable a page that includes dangerous instructions, this can happen
			if (!hwbp_unset_watch(address_to_vet))
				warnf("%s Failed to unset hw bp: 0x" PTRSTR "\n", call_get_variant_pidstr().c_str(), address_to_vet);
			set_mmap_table->active_dangerous_instructions.erase(std::pair<unsigned long, bool>(address_to_vet, is_XRSTOR));
		}

		// Black Hole comment see before
	}
}

/*-----------------------------------------------------------------------------
    discard_pending_signal
-----------------------------------------------------------------------------*/
std::vector<mvee_pending_signal>::iterator
monitor::discard_pending_signal(std::vector<mvee_pending_signal>::iterator& it)
{
	auto ret = pending_signals.erase(it);
	return ret;
}

/*-----------------------------------------------------------------------------
    have_pending_signals
-----------------------------------------------------------------------------*/
bool monitor::have_pending_signals()
{
	return !pending_signals.empty();
}

/*-----------------------------------------------------------------------------
    in_signal_handler
-----------------------------------------------------------------------------*/
bool monitor::in_signal_handler()
{
	return current_signal != 0;
}

/*-----------------------------------------------------------------------------
    sig_prepare_delivery - called from mvee_mon_handle_syscall_entrance_event
    when ALL variants are synced on the same syscall entrance.

    Should inspect the pending signal queue and the current blocked_signals mask
    and possibly prepare a signal for delivery. If a signal is prepared,
    the variants' contexts should be backed up and the current syscall should be
    skipped.
-----------------------------------------------------------------------------*/
bool monitor::sig_prepare_delivery()
{
	if (in_signal_handler() ||
		!have_pending_signals())
		return false;

	bool result = true;

	// keep the sighand table locked so the sig handlers cannot be changed
	// while we prepare a signal for delivery
	set_sighand_table->grab_lock();
	auto it     = pending_signals.begin();
	while (it != pending_signals.end()) {
		// check if the group is willing to accept the signal
		if (sigismember(&blocked_signals[0], it->sig_no)) {
			bool dont_block = false;

			if (variants[0].callnum == __NR_rt_sigsuspend) {
				// sigsuspend might be about to unblock the signal we're checking
				sigset_t _set = call_get_sigset((void*)ARG1(0), OLDCALLIFNOT(__NR_rt_sigsuspend));

				if (!sigismember(&_set, it->sig_no))
					dont_block = true;
			}

			if (!dont_block) {
				debugf("not delivering signal: %s (signal is currently blocked)\n", getTextualSig(it->sig_no));
				it++;
				continue;
			}
		}

		// check if the signal is handled
		if (set_sighand_table->action_table[it->sig_no].sa_handler == SIG_IGN
			|| (set_sighand_table->action_table[it->sig_no].sa_handler == SIG_DFL
				&& sighand_table::is_default_ignored_signal(it->sig_no)))
		{
			debugf("not delivering signal: %s (signal is currently ignored)\n", getTextualSig(it->sig_no));
			mvee::log_sigaction(&set_sighand_table->action_table[it->sig_no]);
			it = discard_pending_signal(it);
			continue;
		}

		// check if every variant has received the signal
		// TODO: Check which other signals this should apply to
		if (it->sig_no == SIGCHLD
			|| it->sig_no == SIGCANCEL)
		{
			unsigned short expected_recv_mask = 0;
			expected_recv_mask |= (1 << 0);
			if (it->sig_recv_mask != expected_recv_mask) {
				debugf("not delivering signal: %s (signal has not been received by all variants)\n", getTextualSig(it->sig_no));
				it++;
				continue;
			}
		}

		debugf("found that the group will accept signal: %s\n", getTextualSig(it->sig_no));

		// found a signal to deliver
		auto tmp = new siginfo_t;
		memcpy(tmp, &it->sig_info, sizeof(siginfo_t));
		current_signal_sent = false;
		current_signal      = it->sig_no;
		current_signal_info = tmp;

		// reset handlers for SA_RESETHAND signals
		if (set_sighand_table->action_table[it->sig_no].sa_flags & SA_RESETHAND)
			set_sighand_table->action_table[it->sig_no].sa_handler = SIG_DFL;

		// delete from pending list
		it                  = discard_pending_signal(it);

		// backup context
		memcpy(&variants[0].regsbackup, &variants[0].regs, sizeof(PTRACE_REGS));
		variants[0].callnumbackup = variants[0].callnum;

		if (variants[0].callnum == __NR_rt_sigsuspend) {
			// we should be at the entry site now...
			if (variants[0].restarted_syscall) {
				debugf("We're in a restarted sys_[rt_]sigsuspend, we can deliver the signal right away!\n");
				result = true;
			}
			else {
				debugf("We're at the sys_[rt_]sigsuspend entry\n");
				result = false;
			}

			variants[0].current_signal_ready = false;

			if (!interaction::signal(variants[0].variantpid,
									 variants[0].varianttgid,
									 current_signal))
			{
				throw SignalFailure(0, current_signal);
			}

			// If we're at the entry of a sigsuspend that hasn't been restarted yet, we will call the precall handler next
			if (result)
				call_resume();

			current_signal_sent = true;
		}
		else {
			debugf("Skipping current syscall in the variant\n");
			call_resume_fake_syscall();
			result = true;
		}

		set_sighand_table->release_lock();
		return result;
	}

	// no eligible signal found, sighand lock can be released
	set_sighand_table->release_lock();
	return false;
}

/*-----------------------------------------------------------------------------
    sig_finish_delivery - we still have the sighand lock at this point
    It is not safe to release it yet until the signal is injected. This
    is called from mvee_mon_handle_syscall_exit_event
-----------------------------------------------------------------------------*/
void monitor::sig_finish_delivery ()
{
	debugf("delivering signal: %s\n", getTextualSig(current_signal));

	// jump to the infinite loop while we wait for async signal delivery
	PTRACE_REGS tmp{};
	memcpy(&tmp, &variants[0].regs, sizeof(PTRACE_REGS));
	IP_IN_REGS(tmp) = (unsigned long) variants[0].infinite_loop_ptr;

	if (!interaction::write_all_regs(variants[0].variantpid, &tmp))
		throw RwRegsFailure(0, "jump to infinite loop");

	if (!interaction::resume(variants[0].variantpid))
		throw ResumeFailure(0, "resume in infinite loop");

	variants[0].current_signal_ready = false;

	if (!interaction::signal(variants[0].variantpid,
							 variants[0].varianttgid,
							 current_signal))
		throw SignalFailure(0, current_signal);

	current_signal_sent = true;
}

/*-----------------------------------------------------------------------------
    mvee_sig_return_from_sighandler - restores original context and resumes variants
-----------------------------------------------------------------------------*/
void monitor::sig_return_from_sighandler()
{
	// restore normal execution after return from signal handler
	debugf("All variants have returned from the sig handler\n");

	// we only set mvee_active_monitor->current_signal for asynchronous signal delivery
	bool restore_context = current_signal ? true : false;
	current_signal      = 0;
	current_signal_sent = false;
	SAFEDELETE(current_signal_info);

	if (variants[0].callnumbackup == __NR_rt_sigsuspend) {
		debugf("We delivered the signal during sys_[rt_]sigsuspend.\n");
		restore_context = false;
		variants[0].callnum = variants[0].callnumbackup;
	}

	if (restore_context) {
		debugf("%s - restoring call site for call: %lu (%s)\n",
			   call_get_variant_pidstr().c_str(),
			   variants[0].callnumbackup,
			   getTextualSyscall(variants[0].callnumbackup));
		variants[0].callnum         = NO_CALL;
		state                       = STATE_NORMAL;

		// explicitly restore the original call number (sometimes required)
		debugf("%s - restoring instruction pointer: 0x" PTRSTR " - syscall no: 0x" PTRSTR "\n",
			   call_get_variant_pidstr().c_str(), (unsigned long)IP_IN_REGS(variants[0].regsbackup), variants[0].callnumbackup);

		// Move the instruction pointer back by 2 bytes to repeat the original syscall
		IP_IN_REGS(variants[0].regsbackup) -= SYSCALL_INS_LEN;
		NEXT_SYSCALL_NO_IN_REGS(variants[0].regsbackup) = variants[0].callnumbackup;
		if (!interaction::write_all_regs(variants[0].variantpid, &variants[0].regsbackup))
			throw RwRegsFailure(0, "post-signal context restore");

		call_resume();

		if (!restore_context && !current_signal)
			call_resume();
	}
}

/*-----------------------------------------------------------------------------
    sig_restart_syscall - for ERESTART_RESTARTBLOCK the kernel will set
    the syscall no to __NR_restart_syscall.

    For other error codes, the syscall no is restored to the original one

    For all restart errors, the kernel will adjust the instruction pointer
    so that we're back at the start of the original syscall
-----------------------------------------------------------------------------*/
void monitor::sig_restart_syscall()
{
	debugf("%s - Restarting syscall %lu (%s) - previous call failed with error: %s\n",
		   call_get_variant_pidstr().c_str(),
		   variants[0].callnum,
		   getTextualSyscall(variants[0].callnum),
		   getTextualKernelError(-variants[0].return_value));

	call_resume();
	variants[0].restarting_syscall = true;
	variants[0].restarted_syscall  = false;
}

/*-----------------------------------------------------------------------------
    hwbp_refresh_regs - helper function. rewrites all debugging
    registers for the specified task, based on the current values of the
    hw_bps and hw_bps_types arrays

    Debug regs are only set for the local thread, not the entire process!
-----------------------------------------------------------------------------*/
void monitor::hwbp_refresh_regs()
{
	unsigned long dr7;
	int           i;

	// Dr0-3 are linear addresses
	for (i = 0; i < 4; ++i) {
		if (variants[0].hw_bps[i]) {
			debugf("%s - setting debug reg %d\n", call_get_variant_pidstr().c_str(), i);
			if (!interaction::write_specific_reg(variants[0].variantpid,
												 offsetof(user, u_debugreg) + i*sizeof(unsigned long), 
												 variants[0].hw_bps[i]))
				throw RwRegsFailure(0, "hwbp set debug reg");
		}
	}

	// Dr6 is the status register, we shouldn't really touch it here...
	// Dr7 is the control register, it specifies whether or not a bp is
	// enabled (locally and/or globally), the length of the data to watch
	// and the type of bp (execution/writes/reads)
	dr7 = 0;

	for (i = 0; i < 4; ++i) {
		if (variants[0].hw_bps[i]) {
			// set locally enabled flag
			dr7 |= 0x1 << i*2;
			// set read/write flag
			if (variants[0].hw_bps_type[i] == MVEE_BP_EXEC_ONLY_XRSTOR) { // this is a virtual type not a real one
				dr7 |= MVEE_BP_EXEC_ONLY << (16 + i * 4);
			}
			else {
				dr7 |= variants[0].hw_bps_type[i] << (16 + i * 4);
			}

			// set len flag (we always assume word length) - len should be 0 for EXEC-only breakpoints
			if ((variants[0].hw_bps_type[i] != MVEE_BP_EXEC_ONLY) && (variants[0].hw_bps_type[i] != MVEE_BP_EXEC_ONLY_XRSTOR))
				dr7 |= 0x3 << (18 + i*4);
				//dr7 |= 0x0 << (18 + i*4);
		}
	}

	debugf("%s - setting ctrl reg\n", call_get_variant_pidstr().c_str());
	if (!interaction::write_specific_reg(variants[0].variantpid,
										 offsetof(user, u_debugreg) + 7*sizeof(long),
										 dr7))
		throw RwRegsFailure(0, "hwbp set dr7");
}

/*-----------------------------------------------------------------------------
    hwbp_set_watch - sets a hardware breakpoint on the specified data
    address (if debug registers are available)

    Debug regs are only set for the local thread, not the entire process!
-----------------------------------------------------------------------------*/
bool monitor::hwbp_set_watch(unsigned long addr, unsigned char bp_type)
{
	int i;

	// check if we've already registered this data watch...
	for (i = 0; i < 4; ++i)
		if (variants[0].hw_bps[i] == addr
			&& variants[0].hw_bps_type[i] == bp_type)
			return true;

	// check if we have room for another bp
	for (i = 0; i < 4; ++i)
		if (!variants[0].hw_bps[i])
			break;

	if (i >= 4) {
		warnf("%s - we already use the maximum number of hw bp\n", call_get_variant_pidstr().c_str());
		return false;
	}

	variants[0].hw_bps[i]      = addr;
	variants[0].hw_bps_type[i] = bp_type;
	hwbp_refresh_regs();
	debugf("%s - set hw bp: 0x" PTRSTR "\n", call_get_variant_pidstr().c_str(), addr);

	return true;
}

/*-----------------------------------------------------------------------------
    hwbp_unset_watch - removes a hardware breakpoint on the specified
    data address
-----------------------------------------------------------------------------*/
bool monitor::hwbp_unset_watch(unsigned long addr)
{
	int i;

	for (i = 0; i < 4; ++i) {
		if (variants[0].hw_bps[i] == addr) {
			debugf("%s - unset hw bp: 0x" PTRSTR "\n", call_get_variant_pidstr().c_str(), addr);
			variants[0].hw_bps[i] = 0;
			break;
		}
	}

	if (i >= 4)
		return false;

	hwbp_refresh_regs();
	return true;
}

/*-----------------------------------------------------------------------------
    get_triggered_watch - gets index of triggered watch (if one is triggered)
    otherwise returns -1
-----------------------------------------------------------------------------*/
int monitor::get_triggered_watch()
{
	int i;
	unsigned long dr6;

	if (!interaction::read_specific_reg(variants[0].variantpid,
										offsetof(user, u_debugreg) + 6*sizeof(long), dr6))
	{
		warnf("%s - Couldn't read dr6\n", call_get_variant_pidstr().c_str());
		return -1;
	}

	for (i = 0; i < 4; ++i)  {
		if (dr6 & (1 << i))  {
			return i;
		}
	}

	return -1;
}

/*-----------------------------------------------------------------------------
    clear_all_watches - clear all watches for the variant
-----------------------------------------------------------------------------*/
void monitor::clear_all_watches()
{
	for (int i = 0; i < 4; ++i) {
		if (variants[0].hw_bps[i])
			debugf("%s - unset hw bp: 0x" PTRSTR "\n", call_get_variant_pidstr().c_str(), variants[0].hw_bps[i]);
		variants[0].hw_bps[i] = 0;
	}
	hwbp_refresh_regs();
}

/*-----------------------------------------------------------------------------
    thread - monitors can either block on the cond_wait
    call in the beginning or on the waitpid call in their normal iteration.

    We can unblock the former by calling cond_signal from the primary thread
    and the latter by sending a signal.
-----------------------------------------------------------------------------*/
void  dummy_handler(int sig)
{}

void* monitor::thread(void* param)
{
	interaction::mvee_wait_status status{};
	auto               mon = (monitor*)param;
	mvee::active_monitor   = mon;
	mvee::active_monitorid = mon->monitorid;
	mon->monitor_tid       = mvee::os_gettid();

	debugf("monitor running! - created by monitor: %d\n", mon->parentmonitorid);

	// super hack! if we ignore SIGCHLD, we won't get a mini
	// thundering herd effect when another monitor thread's variant are reporting CLDSTOP
	struct sigaction act{};
	memset(&act, 0, sizeof(struct sigaction));
	act.sa_handler = SIG_IGN;
	sigaction(SIGCHLD, &act, nullptr);

	// We also ignore this one. It will still interrupt our wait calls though
	act.sa_handler = dummy_handler;
	if (sigaction(SIGUSR1, &act, nullptr))
		warnf("couldn't ignore SIGUSR1\n");

	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGINT);
	pthread_sigmask(SIG_BLOCK, &set, nullptr);

	// wait until we can run
	while (true) {
		if (mon->should_shutdown) {
			mon->shutdown(true);
			return nullptr;
		}

		pthread_mutex_lock(&mon->monitor_lock);
		if (mon->monitor_registered) {
			pthread_mutex_unlock(&mon->monitor_lock);
			break;
		}

		pthread_cond_wait(&mon->monitor_cond, &mon->monitor_lock);
		pthread_mutex_unlock(&mon->monitor_lock);
	}

	debugf("monitor is now registered!\n");
	mon->handle_attach_event();

	try {
		while (true) {
			if (mon->should_shutdown) {
				mon->shutdown(true);
				return nullptr;
			}

			// Standard blocking wait for all of our variants
			if (interaction::wait(-1, status)) {
				mon->handle_event(status);

				// Don't go back into a blocking wait right away... first
				// see if we already have a pending event
				if (interaction::wait(-1, status, true, true) && status.reason != STOP_NOTSTOPPED)
					mon->handle_event(status);
			}
			else {
				debugf("wait failed - error: %s - status: %s\n", getTextualErrno(errno), getTextualMVEEWaitStatus(status).c_str());
			}
		}
	}
	catch (MVEEBaseException& e) {
		if (mon->set_mmap_table && !mon->set_mmap_table->thread_group_shutting_down)
			warnf("caught fatal monitor exception: %s\n", e.what());
		else
			debugf("caught monitor exception during shutdown: %s\n", e.what());
		mon->shutdown(false);
		return nullptr;
	}

	mon->shutdown(true);
	return nullptr;
}
