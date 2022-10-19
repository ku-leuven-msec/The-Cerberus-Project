/*
 * Cerberus PKU-based Sandbox
 *
 * Check Cerberus/cerberus_ReMon/README.md for licensing terms.
 */

#ifndef MVEE_FAKE_SYSCALL_H_INCLUDED
#define MVEE_FAKE_SYSCALL_H_INCLUDED

/*-----------------------------------------------------------------------------
 Constants
 -----------------------------------------------------------------------------*/

#define MVEE_RDTSC_FAKE_SYSCALL        MVEE_FAKE_SYSCALL_BASE + 1

//
// MVEE_RUNS_UNDER_MVEE_CONTROL: Can be used to check if the program runs
// under MVEE control
//
#define MVEE_RUNS_UNDER_MVEE_CONTROL   MVEE_FAKE_SYSCALL_BASE + 9

//
// MVEE_INVOKE_LD: transfer control to ld-linux
//
#define MVEE_INVOKE_LD                 MVEE_FAKE_SYSCALL_BASE + 16

//
// MVEE_JUMPS_SETUP: passes a pointer to a code region to the monitor. This region includes instructions
// that the monitor forces the variants to jump at arbitrary stops.
//
// usage:
// syscall(MVEE_JUMPS_SETUP, addr_of_syscall_jump, addr_of_get_pku_domain_jump);
#define MVEE_JUMPS_SETUP               MVEE_FAKE_SYSCALL_BASE + 42

//
// MVEE_GET_SENSITIVE_INODE: returns sensitive inode that should never be opened
//
#define MVEE_GET_SENSITIVE_INODE       MVEE_FAKE_SYSCALL_BASE + 43

//
// MVEE_SPECIAL_PAGE_SETUP: sets up special page
//
#define MVEE_SPECIAL_PAGE_SETUP        MVEE_FAKE_SYSCALL_BASE + 44

#endif // MVEE_FAKE_SYSCALL_H_INCLUDED
