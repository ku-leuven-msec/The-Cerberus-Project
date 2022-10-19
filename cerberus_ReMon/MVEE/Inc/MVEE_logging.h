/*
 * Cerberus PKU-based Sandbox
 *
 * Check Cerberus/cerberus_ReMon/README.md for licensing terms.
 */

#ifndef MVEE_LOGGING_H_INCLUDED
#define MVEE_LOGGING_H_INCLUDED

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include <sched.h>
#include <string>
#include "MVEE_build_config.h"
#include "MVEE_interaction.h"

/*-----------------------------------------------------------------------------
    Logging Prototypes
-----------------------------------------------------------------------------*/
#define LOCALLOGNAME         "%s/Logs/MVEE_%d.log"
#define LOGDIR               "./Logs/"
#define LOGNAME              "./Logs/MVEE.log"

/*-----------------------------------------------------------------------------
    Logging String Helpers
-----------------------------------------------------------------------------*/
//
// Functions for converting numeric identifiers to text
//
const char* getTextualState             (unsigned int dwState);
const char* getTextualSig               (unsigned int dwSignal);
const char* getTextualSigHow            (int how);
const char* getTextualPtraceRequest     (unsigned int dwRequest);
const char* getTextualSyscall           (long int syscallnum);
const char* getTextualSEGVCode          (int code);
const char* getTextualKernelError       (int err);
const char* getTextualBreakpointType    (int bp_type);
const char* getTextualErrno             (int err);
const char* getTextualMremapFlags       (int flags);
std::string getTextualFileFlags         (int flags);
std::string getTextualFileMode          (int mode);
std::string getTextualProtectionFlags   (int mode);
std::string getTextualCloneFlags        (unsigned int flags);
std::string getTextualMapType           (int mode);
std::string getTextualSigSet            (sigset_t set);
std::string getTextualMSyncFlags        (int flags);
std::string getTextualSigactionFlags    (unsigned int flags);
std::string getTextualPerfFlags         (unsigned long flags);
std::string getTextualMVEEWaitStatus    (interaction::mvee_wait_status& status);

#endif // MVEE_LOGGING_H_INCLUDED
