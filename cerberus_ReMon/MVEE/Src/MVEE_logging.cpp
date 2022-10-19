/*
 * Cerberus PKU-based Sandbox
 *
 * Check Cerberus/cerberus_ReMon/README.md for licensing terms.
 */

/*-----------------------------------------------------------------------------
    Global Variables
-----------------------------------------------------------------------------*/
#include <cstdarg>
#include <sstream>
#include <sys/time.h>
#include <cstring>
#include <algorithm>
#include "MVEE.h"
#include "MVEE_monitor.h"
#include "MVEE_logging.h"
#include "MVEE_private_arch.h"
#include "MVEE_mman.h"
#include "MVEE_memory.h"
#include "MVEE_interaction.h"

/*-----------------------------------------------------------------------------
    Static Variable Initialization
-----------------------------------------------------------------------------*/
FILE*             mvee::logfile              = nullptr;
double            mvee::startup_time         = 0.0;
pthread_mutex_t   mvee::loglock              = PTHREAD_MUTEX_INITIALIZER;

/*-----------------------------------------------------------------------------
    log_init - opens the monitor-specific logfile
-----------------------------------------------------------------------------*/
void monitor::log_init()
{
#ifndef MVEE_BENCHMARK
	char filename[1024];
	sprintf(filename, LOCALLOGNAME, mvee::os_get_orig_working_dir().c_str(), monitorid);
	monitor_log = fopen64(filename, "w");
	if (!monitor_log)
		perror("Failed to open local logfile");
#endif
}

/*-----------------------------------------------------------------------------
    log_fini - closes the monitor-specific logfile
-----------------------------------------------------------------------------*/
void monitor::log_fini()
{
#ifndef MVEE_BENCHMARK
	if (monitor_log)
		fclose(monitor_log);
	monitor_log = nullptr;
#endif
}

/*-----------------------------------------------------------------------------
    log_segfault - Logs segfault (SIGSEGV) info.
-----------------------------------------------------------------------------*/
void monitor::log_segfault()
{
	siginfo_t siginfo;
	unsigned long eip = 0;

	if (!interaction::get_signal_info(variants[0].variantpid, &siginfo)) {
		warnf("%s - Couldn't get signal info\n", call_get_variant_pidstr().c_str());
		return;
	}

	if (!interaction::fetch_ip(variants[0].variantpid, eip))
		warnf("%s - Couldn't read instruction pointer\n", call_get_variant_pidstr().c_str());

	warnf("Warning: %s in variant %d (PID: %d)\n", getTextualSig(siginfo.si_signo), 0, variants[0].variantpid);
	warnf("IP: " PTRSTR ", Address: " PTRSTR ", Code: %s (%d), Errno: %d\n",
		  eip, (unsigned long)siginfo.si_addr, getTextualSEGVCode(siginfo.si_code), siginfo.si_code, siginfo.si_errno);
}

/*-----------------------------------------------------------------------------
    log_hw_bp_event -
-----------------------------------------------------------------------------*/
void monitor::log_hw_bp_event()
{
	int i;
	unsigned long dr6;

	debugf("Hardware Breakpoint hit by variant: %d\n", variants[0].variantpid);

	if (!interaction::read_specific_reg(variants[0].variantpid,offsetof(user, u_debugreg) + 6*sizeof(long), dr6)) {
		warnf("%s - Couldn't read dr6\n", call_get_variant_pidstr().c_str());
		return;
	}

	for (i = 0; i < 4; ++i) {
		if (dr6 & (1 << i)) {
			unsigned long ptr;
			if (!rw::read_primitive<unsigned long>(variants[0].variantpid, (void*) variants[0].hw_bps[i], ptr)) {
				warnf("%s - Couldn't read value at address 0x" PTRSTR " - This address was set in HW BP register %d\n",
					  call_get_variant_pidstr().c_str(), variants[0].hw_bps[i], i);
			}
			else {
				debugf("> this BP at address " PTRSTR " is registered in slot %d and has type %s\n",
					   variants[0].hw_bps[i], i,
					   getTextualBreakpointType(variants[0].hw_bps_type[i]));
				debugf("> current value -> " LONGRESULTSTR " \n", ptr);
			}
			break;
		}
	}

	if (i >= 4)
		warnf("> couldn't find the BP in the BP list...\n");
}

/*-----------------------------------------------------------------------------
    clear_log_folder - called during startup
-----------------------------------------------------------------------------*/
void mvee::clear_log_folder()
{
	char cmd[1024];

	// create the folder if needed
	sprintf(cmd, "mkdir -p %s", LOGDIR);
	if (system(cmd) < 0)
		printf("Couldn't create MVEE log folder: %s\n", LOGDIR);

	// delete any existing logfiles
	sprintf(cmd, "rm -f %s*.log 2>&1", LOGDIR);
	if (system(cmd) < 0)
		printf("Couldn't clear MVEE log folder: %s\n", LOGDIR);
}

/*-----------------------------------------------------------------------------
    log_init - opens the global monitor log
-----------------------------------------------------------------------------*/
void mvee::log_init()
{
#ifndef MVEE_BENCHMARK
	mvee::clear_log_folder();
	printf("Opening MVEE Monitor Log @ %s\n", LOGNAME);
	mvee::logfile              = fopen64(LOGNAME, "w");
	if (mvee::logfile == nullptr)
		perror("Failed to open monitor log");
#endif

	struct timeval tv{};
	gettimeofday(&tv, nullptr);
	mvee::startup_time          = tv.tv_sec + tv.tv_usec / 1000000.0;
}

/*-----------------------------------------------------------------------------
    log_fini
-----------------------------------------------------------------------------*/
void mvee::log_fini(bool terminated)
{
	if (terminated) {
		struct timeval tv{};
		gettimeofday(&tv, nullptr);
		double currenttime = tv.tv_sec + tv.tv_usec / 1000000.0;

#ifndef MVEE_BENCHMARK
		printf("Program terminated after: %lf seconds\n", currenttime - mvee::startup_time);
#else
		fprintf(stderr, "%lf\n", currenttime - mvee::startup_time);
#endif
	}

#ifndef MVEE_BENCHMARK
	sync();
	if (mvee::logfile)
		fclose(mvee::logfile);
#endif
}

/*-----------------------------------------------------------------------------
    warnf - print a warning. Will always log to stdout as well
-----------------------------------------------------------------------------*/
void mvee::warnf(const char* format, ...)
{
	MutexLock lock(&mvee::loglock);
	va_list va;
	va_start(va, format);
	printf("MONITOR[%d] - WARNING: ", mvee::active_monitorid);
	vfprintf(stdout, format, va);
	va_end(va);

#ifndef MVEE_BENCHMARK
	struct timeval tv{};
	double curtime;
	gettimeofday(&tv, nullptr);
	curtime = tv.tv_sec + tv.tv_usec / 1000000.0 - mvee::startup_time;
	if (mvee::active_monitor && mvee::active_monitor->monitor_log) {
		va_list va;
		va_start(va, format);
		fprintf(mvee::active_monitor->monitor_log, "%f - MONITOR[%d] - WARNING: ", curtime, mvee::active_monitorid);
		vfprintf(mvee::active_monitor->monitor_log, format, va);
		va_end(va);
	}

	if (mvee::logfile) {
		va_list va;
		va_start(va, format);
		fprintf(mvee::logfile, "%f - MONITOR[%d] - WARNING: ", curtime, mvee::active_monitorid);
		vfprintf(mvee::logfile, format, va);
		va_end(va);
	}
#endif
	va_end(va);
}

//
// Logging functions
//

/*-----------------------------------------------------------------------------
    logf - print formatted text into the logfile
-----------------------------------------------------------------------------*/
void mvee::logf(const char* format, ...)
{
#ifndef MVEE_BENCHMARK
	struct timeval tv{};
	double curtime;
	gettimeofday(&tv, nullptr);
	curtime = tv.tv_sec + tv.tv_usec / 1000000.0 - mvee::startup_time;

	if (mvee::active_monitor && mvee::active_monitor->monitor_log) {
		va_list va;
		va_start(va, format);
		fprintf(mvee::active_monitor->monitor_log, "%f - MONITOR[%d] - ", curtime, mvee::active_monitorid);
		vfprintf(mvee::active_monitor->monitor_log, format, va);
		va_end(va);
		fflush(mvee::active_monitor->monitor_log);
	}

	MutexLock lock(&mvee::loglock);
	if ((*mvee::config_monitor)["log_to_stdout"].asBool()) {
		va_list va;
		va_start(va, format);
		printf("MONITOR[%d] - ", mvee::active_monitorid);
		vfprintf(stdout, format, va);
		va_end(va);
	}

	if (mvee::logfile) {
		va_list va;
		va_start(va, format);
		fprintf(mvee::logfile, "%f - MONITOR[%d] - ", curtime, mvee::active_monitorid);
		vfprintf(mvee::logfile, format, va);
		va_end(va);
		fflush(mvee::logfile);
	}
#endif
}

/*-----------------------------------------------------------------------------
    log_read_from_proc_pipe
-----------------------------------------------------------------------------*/
std::string mvee::log_read_from_proc_pipe(const char* proc, size_t* output_length)
{
	int read;
	char tmp_buf[1025];
	std::stringstream ss;
	FILE* fp = popen(proc, "r");

	if (!fp || feof(fp)) {
		warnf("ERROR: couldn't create procpipe: %s\n", proc);
		if (output_length)
			*output_length = 0;
		return "";
	}

	while (!feof(fp)) {
		read = fread(tmp_buf, 1, 1024, fp);
		if (read > 0) {
			tmp_buf[read] = '\0';
			ss << tmp_buf;
		}
	}

	pclose(fp);
	if (output_length)
		*output_length = ss.str().length();
	return ss.str();
}

/*-----------------------------------------------------------------------------
    log_do_hex_dump
-----------------------------------------------------------------------------*/
std::string mvee::log_do_hex_dump(const void* hexbuffer, int buffer_size)
{
	std::stringstream out;
	std::string chars;
	size_t line_len         = strlen("    xxxxxxxx    xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx    ................") + strlen("\n");
	size_t partial_line_len = strlen("    xxxxxxxx    xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx    ");

	for (int i = 0; i < buffer_size; ++i)
	{
		char c = *(char*)((unsigned long)hexbuffer + i);

		// new line
		if (i % 16 == 0)
			out << "    " << STDHEXSTR(8, i) << "    ";

		out << STDHEXSTR(2, ((unsigned char)c));
		chars += (c > 32) ? c : '.';

		// end of group
		if (i % 4 == 3)
			out << " ";

		// end of line
		if (i % 16 == 15)
		{
			out << std::setw(partial_line_len - (out.str().length() % line_len)) << " " << std::setw(0);
			out << chars << "\n";
			chars = "";
		}
	}

	if (!chars.empty())
	{
		out << std::setw(partial_line_len - (out.str().length() % line_len)) << " " << std::setw(0);
		out << chars << "\n";
		chars = "";
	}

	return out.str();
}

/*-----------------------------------------------------------------------------
    mvee_log_print_sigaction
-----------------------------------------------------------------------------*/
void mvee::log_sigaction(struct sigaction* action)
{
#ifndef MVEE_BENCHMARK
	const char* handler = "SIG_PTR";

	if (action->sa_handler == SIG_IGN)
		handler = "SIG_IGN";
	else if (action->sa_handler == SIG_DFL)
		handler = "SIG_DFL";

	debugf("> SIGACTION sa_handler   : 0x" PTRSTR " (= %s)\n", (unsigned long)action->sa_handler, handler);
	debugf("> SIGACTION sa_sigaction : 0x" PTRSTR "\n",        (unsigned long)action->sa_sigaction);
	debugf("> SIGACTION sa_restorer  : 0x" PTRSTR "\n",        (unsigned long)action->sa_restorer);
	debugf("> SIGACTION sa_flags     : 0x%08x (= %s)\n",       action->sa_flags,   getTextualSigactionFlags(action->sa_flags).c_str());
	debugf("> SIGACTION sa_mask      : %s\n",                  getTextualSigSet(action->sa_mask).c_str());
#endif
}
