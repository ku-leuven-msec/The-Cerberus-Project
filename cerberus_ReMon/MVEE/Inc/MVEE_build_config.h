/*
 * Cerberus PKU-based Sandbox
 *
 * Check Cerberus/cerberus_ReMon/README.md for licensing terms.
 */

#ifndef MVEE_BUILD_CONFIG_H_
#define MVEE_BUILD_CONFIG_H_

/*-----------------------------------------------------------------------------
  Monitor Definitions
-----------------------------------------------------------------------------*/
//
// MVEE_BENCHMARK: When this is defined, no messages are logged to the logfile
#define MVEE_BENCHMARK

/*-----------------------------------------------------------------------------
  PKU Definitions
-----------------------------------------------------------------------------*/

//
// MVEE_CERBERUS_KERNEL_PKU_SANDBOX_ENABLED: this enables the CERBERUS kernel PKU sandbox from user space.
// Cerberus kernel PKU sandbox does the following:
//    1) Rejects opening of dangerous files (/proc/<pid>/mem).
//    2) Bypasses ptrace and executes natively system calls that are not security critical.
//
#define MVEE_CERBERUS_KERNEL_PKU_SANDBOX_ENABLED

//
// MVEE_CERBERUS_CP_PKU_SANDBOX_ENABLED: GHUMVEE is extended with a PKU sandbox.
// If this is defined CERBERUS_CP_PKU_SANDBOX is enabled.
//
#define MVEE_CERBERUS_CP_PKU_SANDBOX_ENABLED

//
// MVEE_SUPPORTS_PKU_DOMAINS: If defined, PKU domains are supported.
// Otherwise, there is only one domain. This exists for debugging purposes
// of the infrastructure in machines that do not support PKU domains natively.
//
// #define MVEE_SUPPORTS_PKU_DOMAINS

//
// MVEE_AVOID_VETTING_XRSTOR: avoid vetting XRSTOR instructions.
//
// #define MVEE_AVOID_VETTING_XRSTOR

//
// MVEE_AVOID_VETTING_EXPLICIT_XRSTOR_IN_LIBC_AND_LD: we assume that we use a patched libc and ld
// in which the explicit XRSTOR instructions are followed by a proper check. So any 8-byte aligned
// XRSTOR inside libc or ld are safe (we made sure that explicit XRSTOR instructions are 8-byte
// aligned in libc and ld). Implicit XRSTOR in libc and ld are not safe. In addition, any XRSTOR
// instructions outside libc or ld are considered dangerous.
//
#define MVEE_AVOID_VETTING_EXPLICIT_XRSTOR_IN_LIBC_AND_LD

//
// MVEE_DYNINST_BUGS_TREAT: If defined, we deal with some "possible" bugs in DYNINST
// that affect ERIM rewritten binaries.
//
// https://www-auth.cs.wisc.edu/lists/dyninst-api/2014/msg00323.shtml
//
// #define MVEE_DYNINST_BUGS_TREAT

//
// ENABLE_ERIM_POLICY: Specialized system call policy needed for ERIM
//
// #define ENABLE_ERIM_POLICY

//
// ENABLE_XOM_SWITCH_POLICY: Specialized system call policy needed for Intel XOM-Switch
//
// #define ENABLE_XOM_SWITCH_POLICY

//
// ERIM_INTEGRITY_ONLY: Needed for ERIM-CPI
//
// #define ERIM_INTEGRITY_ONLY

//
// CHECK_IF_INSTRUCTION_EMULATIONS_IS_NEEDED: This is just here to check if any of our benchmarks
// needs to use instruction emulation
// TODO need to fully integrate Jonas' instruction emulation engine
//
#define CHECK_IF_INSTRUCTION_EMULATIONS_IS_NEEDED

//
// MOVE_LOADERS_FUNCTIONALITY_IN_MONITOR: This is here temporarily
// Need to be able to enable/disable the loader from just an option (TODO fix)
// TODO fix this does not work with vanilla glibc
//
// #define MOVE_LOADER_FUNCTIONALITY_IN_MONITOR

#endif /* MVEE_BUILD_CONFIG_H_ */
