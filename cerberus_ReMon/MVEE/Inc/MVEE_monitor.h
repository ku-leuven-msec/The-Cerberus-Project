/*
 * Cerberus PKU-based Sandbox
 *
 * Check Cerberus/cerberus_ReMon/README.md for licensing terms.
 */

#ifndef MVEE_PRIVATE_H_INCLUDED
#define MVEE_PRIVATE_H_INCLUDED

/*-----------------------------------------------------------------------------
  Includes
-----------------------------------------------------------------------------*/
#include <sys/user.h>
#include <cstddef>
#include <cstdio>
#include <csignal>
#include <fcntl.h>
#include <memory>
#include <vector>
#include <deque>
#include <sstream>
#include <utility>
#include <cstdlib>
#include <unistd.h>
#include <cstring>
#include <sys/types.h>
#include <sys/stat.h>
#include <cerrno>
#include <climits>
#include <unordered_map>
#include <algorithm>
#include "MVEE_build_config.h"
#include "MVEE_private_arch.h"
#include "MVEE_interaction.h"
#include "MVEE_mman.h"

/*-----------------------------------------------------------------------------
    Typedefs
-----------------------------------------------------------------------------*/
typedef long (monitor:: *mvee_syscall_handler)(int);
typedef void (monitor:: *mvee_syscall_logger)(int);

//
// procmaps_struct
// @desc hold all the information about an area in the process's  VM
//
typedef struct procmaps_struct
{
	void *addr_start;     //< start address of the area
	void *addr_end;       //< end address
	unsigned long length; //< size of the range

	char perm[5];         //< permissions rwxp
	short is_r;           //< rewrote of perm with short flags
	short is_w;
	short is_x;
	short is_p;

	long offset;          //< offset
	char dev[12];         //< dev major:minor
	int inode;            //< inode of the file that backs the area

	char pathname[600];   //< the path of the file that backs the area
	//chained list
	struct procmaps_struct *next; //< handler of the chained list
} procmaps_struct;

//
// procmaps_iterator
// @desc holds iterating information
//
typedef struct procmaps_iterator
{
	procmaps_struct* head;
	procmaps_struct* current;
} procmaps_iterator;

//
// long_and_bytes
//
typedef union long_and_bytes {
	unsigned char bytes[8];
	long value;
} long_and_bytes;

/*-----------------------------------------------------------------------------
  Constants
-----------------------------------------------------------------------------*/
#define S_FILEMODEMASK                     (S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH)
#define PR_REGISTER_CERBERUS               0xb00b135
//maximum line length in a procmaps file
#define PROCMAPS_LINE_MAX_LENGTH           (PATH_MAX + 100)

/*-----------------------------------------------------------------------------
  Enumerations
-----------------------------------------------------------------------------*/
enum MonitorState
{
	STATE_WAITING_ATTACH, // Waiting to attach to the newly created variants
	STATE_WAITING_RESUME, // Waiting for variants to be ready for resume
	STATE_NORMAL,         // Normal operation - variants are running and not executing a syscall
	STATE_IN_SYSCALL,     // Waiting for syscall to return
	STATE_IN_FORKCALL,    // Waiting for forkcall to return
};

enum ScanType
{
	ONLY_EXEC,     // Scan only exec regions/pages
	ONLY_NON_EXEC, // Scan only non-exec regions/pages
	EVERYTHING     // Scan everything
};

/*-----------------------------------------------------------------------------
  Classes
-----------------------------------------------------------------------------*/
//
// Forward decls
//
class mmap_region_info;
class mmap_table;
class sighand_table;

class mvee_pending_signal
{
public:
	// could also be read from sig_info
	unsigned short sig_no;
	// keeps track of which variants have received the signal (signals
	// originating from within the process need to be received by EVERY variant
	// before they can be delivered)
	unsigned short sig_recv_mask;
	// exact copy of the siginfo_t the variant would have received natively
	siginfo_t      sig_info;
};

class overwritten_syscall_arg
{
public:
	int   syscall_arg_num; // 1 to 6
	long  arg_old_value;   // old value in the register. may be a pointer

	overwritten_syscall_arg();
	~overwritten_syscall_arg();
};

// might have to optimize the layout even further for better cache performance
// the user_regs struct is quite large, especially on AMD64...
class variantstate
{
public:
	pid_t         variantpid;              // Process ID of this variant
	long          prevcallnum;             // Previous system call executed by the variant. Set when the call returns.
	long          callnum;                 // System call number being executed by this variant.
	int           call_flags;              // Result of the call handler
	PTRACE_REGS   regs;                    // Arguments for the syscall are copied into the variantstate just before entering the call
	long          return_value;            // Return of the current syscall.

	unsigned char call_type;               // Type of the current system call, i.e. synced/unsynced/unknown
	bool          regs_valid;              // Are the regs up to date?
	bool          return_valid;            // Is the return value up to date?
	bool          restarted_syscall;       // Did we restart the current syscall? Might happen if a signal has arrived while the variant was in the middle of a blocking syscall
	bool          restarting_syscall;
	bool          variant_terminated;      // Was the variant terminated?
	bool          variant_attached;        // has the target monitor attached to this variant yet?
	bool          variant_resumed;         // variant is waiting for a resume after attach
	bool          current_signal_ready;
	bool          have_overwritten_args;   // Do we have any overwritten syscall args that need to be restored?

	std::unordered_set<std::pair<unsigned long, bool>, PairHashByFirst, PairEqualByFirst>   pending_dangerous_addresses;                        // this is needed for "special" mprotect cases

	// somehow, the sigset gets corrupted across sigprocmask calls...
	sigset_t      last_sigset;

	// Occasionally used vars...
	pid_t         varianttgid;             // Thread Group ID of this variant
	pid_t         pendingpid;              // Process ID of the newly created process/thread
	unsigned long infinite_loop_ptr;       // pointer to the sys_pause loop
	long          callnumbackup;           // Backup of the syscall num. Made when the monitor is delivering a signal
	PTRACE_REGS   regsbackup;              // Backup of the registers. Made when the monitor is delivering a signal
	unsigned long hw_bps[4];               // currently set hardware breakpoints
	unsigned char hw_bps_type[4];          // type of hw bp. 0 = exec only, 1 = write only, 2 = I/O read/write, 3 = data read/write but no instr fetches
	void*         tid_address[2];          // optional pointers to the thread id
	std::string   perf_out;                // Output of the perf program
	Json::Value*  config;                  // Variant-specific config

	std::vector<overwritten_syscall_arg>
				  overwritten_args;

	void*         syscall_jump;
	void*         get_pku_domain_jump;
	void*         special_page;
	bool          first_syscall_after_execve;

	variantstate();
	~variantstate();
};

//
// This class represents the monitors that monitor the variants.  Unless
// otherwise noted, all of member functions are implemented in MVEE_monitor.cpp
//
class monitor
{
	friend class mvee;
public:

	// *************************************************************************
	// Public interface for the MVEE logger
	// *************************************************************************

	//
	// Returns true if this monitor's variants are shutting down
	//
	bool is_group_shutting_down              ();

	// *************************************************************************
	// Public interface for the MVEE monitor management - These functions are
	// available to the main mvee process
	// *************************************************************************

	//
	// Wakes up the monitor and sets its should_shutdown flag
	//
	void  signal_shutdown                     ();

	//
	// Wakes up the monitor and sets its monitor_registered flag, indicating
	// that it can begin executing the main monitor loop
	//
	void  signal_registration                 ();

	//
	// Get the process ids of the variant threads monitored by this monitor
	// 
	std::vector<pid_t>
		  getpids                             ();

	// 
	// Calls pthread_join on the specified monitor's pthread_t object
	//
	void  join_thread                         ();

	// 
	// Get the Task Group ID of the master variant monitored by this monitor
	//
	pid_t get_mastertgid                      ();

	// *************************************************************************
	// Scheduling support
	// ************************************************************************* 

	// *************************************************************************
	// Public variables for the MVEE logger
	// *************************************************************************

	// File handle for this monitor's local log file (i.e. MVEE_<monitorid>.log)
	FILE* monitor_log;

	// Unique identifier for this
	int   monitorid;

	// *************************************************************************
	// System Call Handlers
	// *************************************************************************

	// 
	// Dummy functions called when we don't have a handler for a specific
	// syscall
	//
	long handle_donthave                     (int variantnum);
	long handle_dontneed                     (int variantnum);
	void log_donthave                        (int variantnum);
	void log_dontneed                        (int variantnum);

	// 
	// Syscall handler logging helper
	//
	std::string      call_get_variant_pidstr ();

	//
	// Include an automatically generated syscall handler table. All of these
	// handler functions are implemented in MVEE_syscalls_handlers.cpp
	//
	#include "MVEE_syscall_handler_prototypes.h"

	// *************************************************************************
	// Constructors/Destructors
	// *************************************************************************

	// 
	// Constructor used for the primary monitor thread (i.e. the one that attaches
	// to the initial variant processes)
	//
	monitor(std::vector<pid_t>& pids);

	//
	// Constructor used for the secondary monitor threads (i.e. the monitor threads
	// that attach to descendants of the initial variant processes)
	//
	monitor(monitor* parent_monitor, bool shares_fd_table=false, bool shares_mmap_table=false, bool shares_sighand_table=false, bool shares_tgid=false);
	~monitor();

private:

	// *************************************************************************
	// Main monitor thread function - This runs the main monitoring loop
	// *************************************************************************
	static void* thread                                  (void* param);

	// *************************************************************************
	// System call support (these are all in MVEE_syscalls_support.cpp)
	// These functions mostly support the MVEE<->variant datatransfers
	// *************************************************************************

	//
	// Check if our cached regs variable is still up to date for the variant
	// possibly refreshing it if necessary
	//
	void             call_check_regs                     ();

	// 
	// Returns true if the specified syscall result indicates an error
	//
	bool             call_check_result                   (long int result);

	//
	// Returns the syscall result of the variant
	//
	long             call_postcall_get_variant_result      ();

	// 
	// Overwrite the syscall result for the variant
	//
	void             call_postcall_set_variant_result      (unsigned long result);

	//
	// getter functions. These accept pointers to a specific data structure and
	// do a deep copy to a local data structure.
	//
	sigset_t         call_get_sigset                     (void* sigset_ptr, bool is_old_call);
	struct sigaction call_get_sigaction                  (void* sigaction_ptr, bool is_old_call);

	// *************************************************************************
	// Specific Syscall handlers (these are all in MVEE_syscalls_handlers.cpp)
	// *************************************************************************

	//
	// Fetching the arguments for an execve call is complicated and slow.
	// We therefore use a specialized function that caches the results.
	// 
	void             handle_execve_get_args              ();

	//
	// Argument overwriting support.
	//
	void             call_overwrite_arg_value            (int argnum, long new_value, bool needs_restore);
	void             call_restore_args                   ();

	// *************************************************************************
	// Generic Syscall handlers (these are in MVEE_syscalls.cpp) - This is the
	 // main interface for the general monitor logic implemented in
	// MVEE_monitor.cpp
	// *************************************************************************

	//
	// Resume the variant
	// 
	void          call_resume                         ();

	//
	// Replace the syscall number for a single variant with __NR_getpid and then
	// resume it. This forces the variant to execute sys_getpid instead of
	// the call it was about to execute
	// 
	void          call_resume_fake_syscall            ();

	//
	// The syscall that has just returned for this variant was denied in the 
	// CALL handler. This means that the syscall number was replaced by __NR_getpid
	// and that Cerberus will provide the syscall return value.
	// This function will write that return value based on the information
	// provided by the CALL handler
	//
	void          call_write_denied_syscall_return    ();

	// 
	// Determines if syscall @callnum should be executed in lockstep for the variant
	// 
	// For standard syscalls, this is a wrapper around the get_call_type handle
	// functions for the syscall that is currently being executed by the variant
	//
	unsigned char call_precall_get_call_type          (long callnum);

	//
	// Calls the argument logging function for the specified syscall (if any)
	// A default logging function is called if no specialized logger
	// exists in MVEE_syscall_handlers.cpp
	//
	void          call_precall_log_args               (long callnum);

	//
	// Calls the PRECALL handler for the current syscall. This is only done
	// if the syscall is synced (i.e., lockstepped). The PRECALL handler
	// reads the call arguments and asserts that they are equivalent
	// 
	long          call_precall                        ();

	//
	// Runs the late precall handling (i.e. overwriting syscall results if
	// necessary) for syscalls that are not subject to lockstepping
	// 
	// For standard syscalls, this is a wrapper around the call handler function
	// for the syscall that is currently being executed by the variant
	// 
	long          call_call_dispatch_unsynced         ();

	//
	// Runs the late precall handling (i.e. overwriting syscall results if
	// necessary) for syscalls that are subject to lockstepping
	// 
	// For standard syscalls, this is a wrapper around the call handler function
	// for the syscall that is currently being executed by the variants
	// 
	long          call_call_dispatch                  ();

	//
	// Calls the return logging function for the specified syscall (if any)
	// A default logging function is called if no specialized logger exists
	// in MVEE_syscalls_handlers.cpp
	//
	void         call_postcall_log_return             ();

	//
	// Runs the postcall handling for syscalls that are not subject to
	// lockstepping
	// 
	// For standard syscalls, this is a wrapper around the postcall handler
	// function for the syscall that is currently being executed by the variant
	// 
	long          call_postcall_return_unsynced       ();

	//
	// Runs the postcall handling for syscalls that are subject to lockstepping
	// 
	// For standard syscalls, this is a wrapper around the postcall handler
	// function for the syscall that is currently being executed by the variants
	// 
	long          call_postcall_return                ();

	//
	// Locks the specified set of locks. We use these locks to prevent
	// related syscall from being executed simultaneously
	//
	void          call_grab_locks                     (unsigned char syslocks);

	// 
	// Releases the specified set of locks.
	// 
	void          call_release_locks                  (unsigned char syslocks);

	// 
	// Helper functions for syslock locking
	//
	void          call_grab_syslocks                  (unsigned long callnum, unsigned char which);
	void          call_release_syslocks               (unsigned long callnum, unsigned char which);

	// *************************************************************************
	// Event handling - This is all of the non-syscall related event handling
	// These functions are implemented in MVEE_monitor.cpp
	// *************************************************************************

	//
	// Processes a signal delivery to the variant.
	//
	void handle_signal_event                 (interaction::mvee_wait_status& status);

	//
	// Special handling of Hardware Breakpoints
	//
	void handle_hw_bp_event_v1               (interaction::mvee_wait_status& status);
	void handle_hw_bp_event_v2               (interaction::mvee_wait_status& status);

	//
	// Handle detected "dangerous" instructions that could modify PKRU
	// !!! This should only be called at posthandlers of system calls or when we handle a signal !!!
	//
	void handle_dangerous_instruction        (unsigned long address_to_vet, bool is_XRSTOR, bool is_deleted);

	//
	// Generic SIGTRAP handling. 
	//
	void handle_trap_event                   ();

	// 
	// Processes the creation of a new task by the variant
	//
	void handle_fork_event                   (interaction::mvee_wait_status& status);

	//
	// Processes the entrance into a syscall by the variant. This function
	// only implements the really high-level syscall handling logic and relies
	// on the generic syscall handler functions in MVEE_syscalls.cpp to handle
	// the specifics.
	//
	void handle_syscall_entrance_event       ();

	// 
	// Processes the return from a syscall by the variant. This function only implements
	// the really high-level syscall handling logic and relies on the generic
	// syscall handler functions in MVEE_syscalls.cpp to handle the specifics.
	//
	void handle_syscall_exit_event           ();

	//
	// Processes a SIGSYSTRAP signal. This function figures out if the signal
	// was caused by a syscall entrance or exit and delegates to one of the
	// above functions accordingly
	//
	void handle_syscall_event                ();

	// 
	// Processes the death of the variant.
	//
	void handle_exit_event                   ();

	//
	// Processes the first SIGSTOP we see from the variant, which we have not attached to yet
	//
	void handle_attach_event                 ();

	//
	// Processes the second SIGSTOP we see from the variant. This second
	// SIGSTOP is caused by our attach operation.
	//
	void handle_resume_event                 ();

	//
	// Handles an event from a variant we are not currently attached to
	//
	void handle_detach_event                 (int variantpid);

	// 
	// Entrypoint for all event handling
	//
	void handle_event                        (interaction::mvee_wait_status& status);

	// *************************************************************************
	// Signal specific event handling
	// *************************************************************************

	//
	// Removes the specified signal from this monitor's pending_signals list,
	// preventing future delivery of said signal to the variants
	//
	std::vector<mvee_pending_signal>::iterator discard_pending_signal              (std::vector<mvee_pending_signal>::iterator& it);

	//
	// Checks if we have pending signals
	//
	bool                                       have_pending_signals                ();

	//
	// Checks if the variants are in a signal handler
	//
	bool                                       in_signal_handler                   ();

	//
	// Inspects the pending_signals list and possibly initiates the delivery
	// of one of the pending signals to the variants. Returns true if a signal
	// delivery was initiated
	//
	bool                                       sig_prepare_delivery                ();

	//
	// Finishes the delivery of a signal whose delivery was initiated in a
	// preceding sig_prepare_delivery call
	//
	void                                       sig_finish_delivery                 ();

	//
	// Handles the execution of sys_rt_sigreturn calls. This call is executed
	// when the the execution of a signal handler finishes. This function should
	// restore the original register context for each variant and resume them
	//
	void                                       sig_return_from_sighandler          ();

	//
	// Handle ERESTART_* errors resulting from signal deliveries during blocking
	// syscalls.
	//
	void                                       sig_restart_syscall                 ();

	// *************************************************************************
	// Hardware breakpoint support and more Cerberus goodies
	// *************************************************************************

	// 
	// Update variant's debug registers after we have set or unset a
	// hardware breakpoint
	// 
	void hwbp_refresh_regs              ();

	//
	// Set or remove a hardware breakpoint at address @addr in variant.
	// Refer to MVEE_monitor.h for a list of possible breakpoint types.
	//
	bool hwbp_set_watch                 (unsigned long addr, unsigned char bp_type);
	bool hwbp_unset_watch               (unsigned long addr);
	int  get_triggered_watch            ();
	void clear_all_watches              ();

	//
	// Based on Anjo Vahldiek-Oberwagner's code from https://github.com/vahldiek/erim
	//
	static unsigned long                                                                            erim_scanMemForWRPKRUXRSTOR    (char* mem_start, unsigned long length);
	static int                                                                                      isBenignWRPKRU                 (uint32_t untrustedPKRU, char* loc);
	static std::unordered_set<std::pair<unsigned long, bool>, PairHashByFirst, PairEqualByFirst>    erim_memScanRegion             (uint32_t untrustedPKRU, char* origstart, unsigned long origlength, const char* pathname);

	//
	// pmparser_parse
	// @param pid the process id whose memory map to be parser. the current process if pid<0
	// @return an iterator over all the nodes
	//
	static procmaps_iterator*                                  pmparser_parse                               (int pid);

	//
	// pmparser_next
	// @description move between areas
	// @param p_procmaps_it the iterator to move on step in the chained list
	// @return a procmaps structure filled with information about this VM area
	//
	static procmaps_struct*                                    pmparser_next                                (procmaps_iterator* p_procmaps_it);

	//
	// pmparser_free
	// @description should be called at the end to free the resources
	// @param p_procmaps_it the iterator structure returned by pmparser_parse
 	//
	static void                                                pmparser_free                                (procmaps_iterator* p_procmaps_it);

	//
	// _pmparser_split_line
	// @description internal usage
	//
	static void                                                _pmparser_split_line                         (char* buf, char* addr1, char* addr2, char* perm, char* offset, char* device, char* inode, char* pathname);

	//
	// pmparser_print
	// @description parses /proc/<pid>/maps and print info of mapped regions
	// @param map the head of the list
	// @order the order of the area to print, -1 to print everything
	// @print_only_executable_areas true for printing only info for the executable areas, false otherwise
	//
	static void                                                pmparser_print                               (procmaps_struct* map, int order, bool print_only_executable_areas);

	//
	// is_region_included
	// @description checks if a "specific" region is included (even partially) in an address range.
	// This method returns true if the region is included (even partially), false otherwise.
	// @start_region start of the region that we want to check
	// @len1 the length of the region that we want to check
	// @addr start of the address range
	// @len2 the length of the address range
	//
	// https://unix.stackexchange.com/questions/6301/how-do-i-read-from-proc-pid-mem-under-linux
	//
	static bool                                                                                       is_region_included                                              (void* start_region, size_t len1, void* addr, size_t len2);

	//
	// pmparser_get_vdso_dangerous_instructions
	// @description gets new dangerous instructions in vdso regions (also gets partial dangerous instructions)
	//
	static std::unordered_set<std::pair<unsigned long, bool>, PairHashByFirst, PairEqualByFirst>      pmparser_get_vdso_dangerous_instructions                        ();

	//
	// pmparser_get_ld_loader_bounds
	// @description parses proc/<pid>/maps to find MVEE_LOADER's mapped regions. Returns true if succeeds or false otherwise.
	//
	static bool                                                                                       pmparser_get_ld_loader_bounds                                   (unsigned long& loader_base, unsigned long& loader_size);

	//
	// pmparser_get_region_info
	// @decription parses /proc/<pid>/maps and returns a region's info (map_flags are not updated for the moment)
	// @address any address of a mapped region
	//
	static mmap_region_info*                                                                          pmparser_get_region_info                                        (unsigned long address);

	//
	// pmparser_get_page
	// @description returns the page starting at @addr or null (if that page is non-existent, non-accessible).
	// If there are some non-accessible bytes at the end of the page, we just populate them with zeroes (this is ok for our current use cases).
	// @p_procmaps_it an iterator to a data structure that contains info about /proc/<pid>/maps (null is also ok).
	// This is just an optimization in order to not parse the /proc/<pid>/maps again.
	// @addr start of the page
	// @type depending on the types only specific pages are scanned
	//
	static char*                                                                                      pmparser_get_page                                               (procmaps_iterator* p_procmaps_it, void* addr, ScanType type);

	//
	// pmparser_get_partial_dangerous_instructions_of_a_region
	// @description parses proc/<pid>/maps to find dangerous instructions between this region and its next and/or previous page (we also call them partial dangerous instructions)
	// @p_procmaps_it an iterator to a data structure that contains info about /proc/<pid>/maps (null is also ok).
	// This is just an optimization in order to not parse the /proc/<pid>/maps again.
	// @buf containing the accessible code of this region
	// @len length of buf
	// @addr start of this region
	// @check_next_page if true check the next page after this region page for partial dangerous instructions, in case that there are partial dangerous instructions at the end of this region
	// @previous_type depending on the types only specific pages are scanned
	// @next_type depending on the types only specific pages are scanned
	//
	static std::unordered_set<std::pair<unsigned long, bool>, PairHashByFirst, PairEqualByFirst>      pmparser_get_partial_dangerous_instructions_of_a_region         (procmaps_iterator* p_procmaps_it, char* buf, size_t len, void* addr, bool check_next_page, ScanType previous_type, ScanType next_type);

	//
	// pmparser_get_partial_dangerous_instructions
	// @description parses proc/<pid>/maps to find "partial" dangerous instructions in this address range (previous and next page of this area range should be executable to return dangerous instructions across them)
	// @addr start of the address range
	// @len length of the address range
	// @region_type depending on the types only specific regions are scanned for partial instructions
	// @pn_type depending on the types only specific pages are scanned
	//
	static std::unordered_set<std::pair<unsigned long, bool>, PairHashByFirst, PairEqualByFirst>      pmparser_get_partial_dangerous_instructions                     (void* addr, size_t len, ScanType region_type, ScanType pn_type);

	//
	// pmparser_get_dangerous_instructions
	// @description parses proc/<pid>/maps to find dangerous instructions in this address range
	// At the moment this method does not get dangerous instructions that cross boundaries ... check pmparser_get_partial_dangerous_instructions.
	// It also optionally includes sanity checks for regions that should never become executable.
	// @addr start of the address range that we want to check
	// @len the length of the address range
	// @sanity_check if true does sanity checkes for regions that should never become executable
	// @type depending on the types only specific regions are scanned
	//
	static std::unordered_set<std::pair<unsigned long, bool>, PairHashByFirst, PairEqualByFirst>      pmparser_get_dangerous_instructions                             (void* addr, size_t len, bool sanity_check, ScanType type);

	// hacky method to check if Intel XOM-Switch policy is violated
	// TODO explain more what it does
	static bool                                                                                       pmparser_is_xom_switch_policy_violated                          (void* addr, size_t len, unsigned long perm);

	//
	// get_deleted_dangerous_instructions
	// @description should be called when we change permissions and make an address range that was executable, non-executable
	// this method returns the virtual addresses of the instructions that we should not vet anymore or nothing
	// @addr start of the address range
	// @len the length of the address range
	//
	static std::unordered_set<std::pair<unsigned long, bool>, PairHashByFirst, PairEqualByFirst>      get_deleted_dangerous_instructions                              (void* addr, size_t len);

	//
	// postcall_set_page_prot_non_exe
	// @description Sets a given page to non-executable or the region's original page
	// Returns 0 if success, -1 otherwise
	// @addr start of the page that we want to change permissions
	// @prot_non_exec if true make page non-executable, else make the page executable
	//
	// !!! This should never be called at precall handlers !!!
	// TODO FIXME if we receive a signal we do not recover
	//
	int  postcall_set_page_prot_non_exec              (unsigned long addr, bool prot_non_exec);

	//
	// postcall_init_cerberus_kernel_pku_sandbox
	// @descriptionInitialize the Cerberus kernel PKU sandbox
	//
	// !!! This should never be called at precall handlers !!!
	// TODO FIXME if we receive a signal we do not recover
	//
	void postcall_init_cerberus_kernel_pku_sandbox    ();

	//
	// precall_open_special_fd
	// @description Opens special fd to special file and returns on success
	// @special_path path to special file
	//
	// !!! This method only works at precall handlers !!!
	// TODO FIXME if we receive a signal we do not recover
	//
	int  precall_open_special_fd                      (const std::string& special_path);

	//
	// precall_syscall
	// @description Executes syscall on the variant
	//
	// !!! This method only works at the syscall entrance !!!
	// TODO FIXME if we receive a signal we do not recover
	//
	long precall_syscall                              (unsigned long syscall_no, unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5, unsigned long arg6);

	// helpful method for creating cerberusmask
	void cerberus_set_unchecked_syscall               (unsigned char* mask, unsigned long syscall_no, unsigned char unchecked);

	//
	// precall_init_cerberus
	// @description Initialize cerberus
	//
	// !!! This method only works at the syscall entrance !!!
	// TODO FIXME If we receive a signal we do not recover
	//
	void precall_init_cerberus                        ();

	//
	// precall_set_infinite_loop
	// @description Set infinite loop
	//
	// !!! This method only works at the syscall entrance !!!
	// TODO FIXME If we receive a signal we do not recover
	//
	void precall_set_infinite_loop                    ();

	//
	// precall_set_jumps_and_special_page
	// @description Set jumps and special page
	//
	// !!! This method only works at the syscall entrance !!!
	// TODO FIXME If we receive a signal we do not recover
	//
	void precall_set_jumps_and_special_page           ();

	//
	// postcall_close_special_fd
	// @description Close special fd to special file
	// @special_fd fd to clode
	//
	// !!! This method only works at postcall handlers !!!
	// TODO FIXME If we receive a signal we do not recover
	//
	void postcall_close_special_fd                    (int special_fd);

	//
	// Gets current PKU domain of the variant when we are at a precall handler
	// !!! This method only works at precall handlers !!!
	// TODO FIXME If we receive a signal we do not recover
	//
	int  precall_get_pku_domain                       ();

	//
	// Getters
	//
	static std::string                                                                                   get_path_from_fd                             (unsigned long fd);
	static std::string                                                                                   get_full_path                                (unsigned long dirfd, void* path_ptr);

	// *************************************************************************
	// Logging/Backtracing functions - These are implemented in MVEE_logging.cpp
	// *************************************************************************

	// 
	// Opens the monitor-local log file (i.e. MVEE_<monitorid>.log)
	//
	void log_init                        ();

	// 
	// Closes the monitor-local log file (i.e. MVEE_<monitorid>.log)
	//
	void log_fini                        ();

	//
	// Error Logging Functions
	//
	void log_segfault                    ();
	void log_hw_bp_event                 ();

	// *************************************************************************
	// Variant Initialization
	// *************************************************************************   

	//
	// Initialize the variantstate struct for the variant
	//
	void        init_variant                    (pid_t variantpid, pid_t varianttgid);

	//
	// Writes new execve arguments to inject the
	// MVEE_LD_Loader/interpreter/library path/...
	//
	void        rewrite_execve_args             ();

	//
	// Serializes a deque by writing a raw serialized buffer and a raw pointer
	// array containing pointers to the elements in the serialized buffer.
	// The pointers are relocated because we assume that the serialized buffer
	// will be written at @target_address
	//
	static void serialize_and_relocate_arr      (std::deque<char*>& arr, char*& serialized, char**& relocated, unsigned long target_address);

	//
	// Get the original execve arguments array for the variant
	//
	std::deque<char*>
				get_original_argv               ();

	// *************************************************************************
	// Monitor startup/shutdown
	// *************************************************************************    

	//
	// Shut down the current monitor thread. This frees all of the resources
	// allocated by this monitor and possibly kills any variants that are still
	// active.
	// Finally, the shutdown function will signal the mvee garbage collection
	// thread by calling mvee::unregister_monitor, and it will then simply wait
	// to be garbage collected.
	//
	void shutdown                            (bool success);

	//
	// Handle any incoming events from variants we have detached from, but are
	// not attached to other monitor threads yet.
	//
	void await_pending_transfers             ();

	//
	// Initialize all of our variables to their default values
	//
	void init();

	//
	// Check if program is multithreaded
	//
	bool is_program_multithreaded        ();

	//
	// Syscall handler tables
	//
	static const mvee_syscall_handler syscall_handler_table [MAX_CALLS][4];
	static const mvee_syscall_logger  syscall_logger_table  [MAX_CALLS][2];

	//
	// Variables
	//
	pthread_t                         monitor_thread;
	pthread_mutex_t                   monitor_lock;
	pthread_cond_t                    monitor_cond;

	bool                              created_by_vfork;
	bool                              should_shutdown;        // set by the management thread
	bool                              call_succeeded;         // Set by the postcall handler when a synced call has succeeded
	bool                              monitor_registered;
	bool                              monitor_terminating;

	int                               parentmonitorid;        // monitorid of the monitor that created this monitor...
	MonitorState                      state;                  //
	std::shared_ptr<mmap_table>
									  set_mmap_table;         // Mmap table for this thread set. Might be shared with a parent thread set

	std::shared_ptr<sighand_table>
									  set_sighand_table;      //

	std::vector<pid_t>                local_detachlist;       // pids of variants that we haven't detached from yet...
	std::vector<pid_t>                unknown_variants;       // pids of variants we've received events from but don't know yet

	// Signal info
	unsigned short                    current_signal;         // signal no for the signal we're currently delivering
	unsigned short                    current_signal_sent;    //
	siginfo_t*                        current_signal_info;    // siginfo for the signal we're currently delivering
	std::vector<mvee_pending_signal>
									  pending_signals;
	std::vector<variantstate>
									  variants;               // State for all variant processes being traced by this monitor
	pid_t                             monitor_tid;

	// set of signals which are currently blocked for this thread set.
	// Blocked signals are added to the pending queue and must be delivered
	// when and if the signal is every unblocked. Duplicates must be discarded
	std::vector<sigset_t>             blocked_signals;
	// previous set of signals which were blocked. this is used for calls
	// that temporarily replace the signal mask (e.g. sigsuspend)
	std::vector<sigset_t>             old_blocked_signals;

#ifdef ENABLE_ERIM_POLICY
	int pkey_mprotect_count;
	std::vector<std::pair<unsigned long, unsigned long>> isolated_regions;
#endif
};

class detachedvariant
{
public:
	pid_t         variantpid;                                 //
	monitor*      new_monitor;                                // monitor the variant should be transferred to
	int           parentmonitorid;                            // id of the monitor this variant was detached from
	int           parent_has_detached;                        // set to true when the original monitor, under whose control this variant was spawned, has detached
	PTRACE_REGS   original_regs;                              // original contents of the registers
	unsigned long transfer_func;                              // pointer to the sys_pause loop
	void*         tid_address[2];                             // set if we should tell the variant what its thread id is (e.g. if the variant was created by clone(CLONE_CHILD_SETTID)

	detachedvariant()
		: variantpid(0)
		, new_monitor(nullptr)
		, parentmonitorid(0)
		, parent_has_detached(0)
		, transfer_func(0)
	{
	}
};

/*-----------------------------------------------------------------------------
  HW breakpoint types
-----------------------------------------------------------------------------*/
#define MVEE_BP_EXEC_ONLY           0
#define MVEE_BP_WRITE_ONLY          1
#define MVEE_BP_READ_WRITE          2
#define MVEE_BP_READ_WRITE_NO_FETCH 3
#define MVEE_BP_EXEC_ONLY_XRSTOR    4 // this is not a real type, just a "virtual" one to be able to separate XRSTOR EXEC_ONLY hw bp

/*-----------------------------------------------------------------------------
  Trap codes
-----------------------------------------------------------------------------*/
#define MVEE_TRAP_BRKPT             (1)                       /* process breakpoint */
#define MVEE_TRAP_TRACE             (2)                       /* process trace trap */
#define MVEE_TRAP_BRANCH            (3)                       /* process taken branch trap */
#define MVEE_TRAP_HWBKPT            (4)                       /* hardware breakpoint/watchpoint */

/*-----------------------------------------------------------------------------
  Kernel Errors
-----------------------------------------------------------------------------*/
#define ERESTARTSYS                 512
#define ERESTARTNOINTR              513
#define ERESTARTNOHAND              514                       /* restart if no handler.. */
#define ENOIOCTLCMD                 515                       /* No ioctl command */
#define ERESTART_RESTARTBLOCK       516                       /* restart by calling sys_restart_syscall */

/* Defined for the NFSv3 protocol */
#define EBADHANDLE                  521                       /* Illegal NFS file handle */
#define ENOTSYNC                    522                       /* Update synchronization mismatch */
#define EBADCOOKIE                  523                       /* Cookie is stale */
#define ENOTSUPP                    524                       /* Operation is not supported */
#define ETOOSMALL                   525                       /* Buffer or request is too small */
#define ESERVERFAULT                526                       /* An untranslatable error occurred */
#define EBADTYPE                    527                       /* Type not supported by server */
#define EJUKEBOX                    528                       /* Request initiated, but will not complete before timeout */
#define EIOCBQUEUED                 529                       /* iocb queued, will get completion event */
#define EIOCBRETRY                  530                       /* iocb queued, will trigger a retry */

#include "MVEE_exceptions.h"

#endif // MVEE_PRIVATE_H_INCLUDED
