/*
 * Cerberus PKU-based Sandbox
 *
 * Check Cerberus/cerberus_ReMon/README.md for licensing terms.
 */

#ifndef MVEE_PRIVATE_ARCH_H_
#define MVEE_PRIVATE_ARCH_H_

#include <asm/unistd_64.h>
#include <sys/reg.h>

/*-----------------------------------------------------------------------------
  Architecture-specific features
-----------------------------------------------------------------------------*/
//
// MVEE_ARCH_ALWAYS_USE_LD_LOADER: this is defined if we always want to load
// variants indirectly using the LD Loader. Normally, the LD Loader is
// only used if we want to hide the VDSO or if we want to apply Disjoint
// Code Layouts.
//
#define MVEE_ARCH_ALWAYS_USE_LD_LOADER

//
// the base constant from which all fake syscall numbers used by the monitor
// are derived
//
#define MVEE_FAKE_SYSCALL_BASE   0x6FFFFFFF

/*-----------------------------------------------------------------------------
  SPEC PROFILES
-----------------------------------------------------------------------------*/
#define SPECPROFILENOPIE           "build_base_spec2006_MVEE_thereisnopie_amd64-nn.0000"
#define SPECPROFILEPIE             "build_base_spec2006_MVEE_pie_amd64-nn.0000"
#define SPECCONFIGNOPIE            "spec2006_MVEE_thereisnopie_amd64"
#define SPECCONFIGPIE              "spec2006_MVEE_pie_amd64"

/*-----------------------------------------------------------------------------
  MVEE LD Loader
-----------------------------------------------------------------------------*/
#define MVEE_ARCH_SUFFIX           "/amd64/"
#define MVEE_ARCH_INTERP_PATH      "/lib64/"
#define MVEE_ARCH_INTERP_NAME      "ld-linux-x86-64.so.2"
#define MVEE_LD_LOADER_PATH        "/MVEE_LD_Loader/"
#define MVEE_LD_LOADER_NAME        "MVEE_LD_Loader_this_is_a_very_long_process_name_that_must_be_at_least_as_long_as_slash_lib64_slash_ld-linux-x86-64.so.2_times_two"
#define MVEE_LD_LOADER_BASE        0x10000000
// From the AMD64 ABI, Section 3.3.2:
// Although the AMD64 architecture uses 64-bit pointers, implementations are only
// required to handle 48-bit addresses. Therefore, conforming processes may only
// use addresses from 0x0000000000000000 to 0x00007fffffffffff
#define HIGHEST_USERMODE_ADDRESS   0x0000800000000000

/*-----------------------------------------------------------------------------
  String Constants
-----------------------------------------------------------------------------*/
#define STDHEXSTR(w, x) std::setw(w) << std::hex << std::setfill('0') << (unsigned long)(x) << std::setfill(' ') << std::setw(0) << std::dec
#define STDPTRSTR(x)    STDHEXSTR(16, x)
#define LONGPTRSTR                 "%016lx"
#define PTRSTR                     "%016lx"
#define LONGRESULTSTR              "%016ld"

/*-----------------------------------------------------------------------------
  Register selection
-----------------------------------------------------------------------------*/
#define PTRACE_REGS struct user_regs_struct
#define SYSCALL_INS_LEN            2

//
// Offsets in user_regs_struct
//
#define SYSCALL_NO_REG_OFFSET      (ORIG_RAX * 8)
#define SYSCALL_RETURN_REG_OFFSET  (RAX * 8)
#define SYSCALL_NEXT_REG_OFFSET    (RAX * 8)
#define IP_REG_OFFSET              (RIP * 8)

// platform independent program counter selection
#define IP_IN_REGS(regs)                                regs.rip
// platform independent stack pointer selection
#define SP_IN_REGS(regs)                                regs.rsp
// platform independent next syscall no selection
#define NEXT_SYSCALL_NO_IN_REGS(regs)                   regs.rax

/*-----------------------------------------------------------------------------
  Syscall argument macros
-----------------------------------------------------------------------------*/

//
// Retrieve the syscall argument of a variant
//
#define ARG1(variantnum)                          variants[variantnum].regs.rdi
#define ARG2(variantnum)                          variants[variantnum].regs.rsi
#define ARG3(variantnum)                          variants[variantnum].regs.rdx
#define ARG4(variantnum)                          variants[variantnum].regs.r10
#define ARG5(variantnum)                          variants[variantnum].regs.r8
#define ARG6(variantnum)                          variants[variantnum].regs.r9
#define SYSCALL_NO(variantnum)                    variants[variantnum].regs.orig_rax

//
// Change the syscall argument of a variant
//
#define SETARG1(variantnum, value)                interaction::write_specific_reg(variants[variantnum].variantpid, RDI * 8, (long)(value))
#define SETARG2(variantnum, value)                interaction::write_specific_reg(variants[variantnum].variantpid, RSI * 8, (long)(value))
#define SETARG3(variantnum, value)                interaction::write_specific_reg(variants[variantnum].variantpid, RDX * 8, (long)(value))
#define SETARG4(variantnum, value)                interaction::write_specific_reg(variants[variantnum].variantpid, R10 * 8, (long)(value))
#define SETARG5(variantnum, value)                interaction::write_specific_reg(variants[variantnum].variantpid, R8 * 8, (long)(value))
#define SETARG6(variantnum, value)                interaction::write_specific_reg(variants[variantnum].variantpid, R9 * 8, (long)(value))
#define SETSYSCALLNO(variantnum, value)           interaction::write_specific_reg(variants[variantnum].variantpid, ORIG_RAX * 8, (long)(value))

#endif /* MVEE_PRIVATE_ARCH_H_ */
