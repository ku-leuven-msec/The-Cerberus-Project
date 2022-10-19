/*
 * Cerberus PKU-based Sandbox
 *
 * Check Cerberus/cerberus_ReMon/README.md for licensing terms.
 */

#ifndef MVEE_SYSCALLS_H_INCLUDED
#define MVEE_SYSCALLS_H_INCLUDED

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include "MVEE_build_config.h"

/*-----------------------------------------------------------------------------
    Syscall Handler Definitions
-----------------------------------------------------------------------------*/
// Types of system call handlers
#define MVEE_GET_CALL_TYPE                0
#define MVEE_HANDLE_PRECALL               1
#define MVEE_HANDLE_CALL                  2
#define MVEE_HANDLE_POSTCALL              3

// Types of system call loggers
#define MVEE_LOG_ARGS                     0
#define MVEE_LOG_RETURN                   1

// Possible return values of the GET_CALL_TYPE system call handler
#define MVEE_CALL_TYPE_UNKNOWN            0
#define MVEE_CALL_TYPE_UNSYNCED           1
#define MVEE_CALL_TYPE_NORMAL             2

// Possible return values of the PRECALL system call handler
#define MVEE_PRECALL_ARGS_MATCH           0x0001                    // All variants have equivalent syscall arguments
#define MVEE_PRECALL_ARGS_MISMATCH(a)     (0x0002 | (a << 6))       // A mismatch was detected in syscall argument nr. <a>
#define MVEE_PRECALL_CALL_DENY            0x0004                    // The variants have diverged. NOTE: We could technically allow a call, despite having an argument mismatch!
#define MVEE_PRECALL_CALL_DISPATCH_NORMAL 0x0008                    // Dispatch as a normal syscall
#define MVEE_PRECALL_CALL_DISPATCH_FORK   0x0010                    // Dispatch as a fork-like syscall
#define MVEE_PRECALL_MISMATCHING_ARG(precall_flags) \
	((precall_flags & (~0x3F)) >> 6)

// Possible return values of the CALL system call handler
#define MVEE_CALL_ALLOW                   0x0001                    // Allow the variant(s) to be resumed from the syscall entry site, without modifying their syscall number or arguments
#define MVEE_CALL_DENY                    0x0002                    // Allow the variant(s) to be resumed from the syscall entry site, but replace their syscall number by __NR_getpid
#define MVEE_CALL_ERROR                   0x0004                    
#define MVEE_CALL_VALUE                   0x0008
#define MVEE_CALL_RETURN_ERROR(a) (0x0004 | (a << 6))               // Used in conjunction with MVEE_CALL_DENY. Return error <a> from the denied syscall (this is equivalent to MVEE_CALL_RETURN_VALUE(-a))
#define MVEE_CALL_RETURN_VALUE(a) (0x0008 | (a << 6))               // Used in conjunction with MVEE_CALL_DENY. Return value <a> from the denied syscall

// Possible return values of the POSTCALL system call handler
#define MVEE_POSTCALL_RESUME              0x0000                    // Default return value for postcall handlers. Resume the variant(s) from the syscall exit site
#define MVEE_POSTCALL_DONTRESUME          0x0001                    // Don't resume the variant(s) from the syscall exit site (used for sigreturn and friends)
#define MVEE_POSTCALL_HANDLED_UNSYNCED_CALL 0x0002

#define MVEE_HANDLER_DONTHAVE             (&monitor::handle_donthave)
#define MVEE_HANDLER_DONTNEED             (&monitor::handle_dontneed)
#define MVEE_LOGGER_DONTHAVE              (&monitor::log_donthave)
#define MVEE_LOGGER_DONTNEED              (&monitor::log_dontneed)


// Types of locks a system call handler might need - these are managed from MVEE/Src/MVEE_syscalls.cpp
#define MVEE_SYSLOCK_MMAN                 (1 << 0)                  // syscall needs mman lock
#define MVEE_SYSLOCK_SIG                  (1 << 1)                  // syscall needs sighand lock
#define MVEE_SYSLOCK_FULL                 (1 << 2)                  // syslocks need to be held accross the call
#define MVEE_SYSLOCK_PRECALL              (1 << 3)                  // syslocks need to be held before the call only
#define MVEE_SYSLOCK_POSTCALL             (1 << 4)                  // syslocks need to be held after the call only

//
// Function declaration macros
//
#define GET_CALL_TYPE(syscall_name) \
	long monitor::handle_##syscall_name##_get_call_type(int variantnum)

#define LOG_ARGS(syscall_name) \
	void monitor::handle_##syscall_name##_log_args(int variantnum)

#define PRECALL(syscall_name) \
	long monitor::handle_##syscall_name##_precall(int variantnum)

#define CALL(syscall_name) \
	long monitor::handle_##syscall_name##_call(int variantnum)

#define POSTCALL(syscall_name) \
	long monitor::handle_##syscall_name##_postcall(int variantnum)

#define LOG_RETURN(syscall_name) \
	void monitor::handle_##syscall_name##_log_return(int variantnum)

#endif // MVEE_SYSCALLS_H_INCLUDED
