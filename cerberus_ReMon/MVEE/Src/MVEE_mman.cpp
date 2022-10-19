/*
 * Cerberus PKU-based Sandbox
 *
 * Check Cerberus/cerberus_ReMon/README.md for licensing terms.
 */

/*
 * NOTES:
 * 1) We try to mimic the kernel's mman bookkeeping, i.e., our bookkeeping
 * should match what we read from /proc/<pid>/maps. At this time though, it's
 * not entirely clear to me what the rules for merging regions are...
 * Anonymous regions are particularly cumbersome. We tend to merge adjacent
 * anonymous regions (provided that they have the same protection flags and so
 * on). The kernel does not seem to merge them every time..
 * Either way, the way MVEE_mman currently works is sufficient for our purposes.
 * We can deduct the properties for every byte of mapped memory from our book-
 * keeping. In the future we might have to reproduce /proc/<pid>/maps even
 * more accurately.
 */

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include <unistd.h>
#include <sys/mman.h>
#include <sstream>
#include <random>
#include <string>
#include <cstring>
#include <stack>
#include <csignal>
#include "MVEE.h"
#include "MVEE_logging.h"
#include "MVEE_mman.h"
#include "MVEE_private_arch.h"
#include "MVEE_macros.h"

/*-----------------------------------------------------------------------------
    mmap_region_info class
-----------------------------------------------------------------------------*/
mmap_region_info::mmap_region_info
(
	unsigned long address,
	unsigned long size,
	unsigned int  prot_flags,
	std::string   backing_file,
	unsigned int  backing_file_offset,
	unsigned int  map_flags
)
	: region_base_address(address),
	region_size(size),
	region_prot_flags(prot_flags),
	region_backing_file_offset(backing_file_offset)
{
	region_map_flags          = map_flags & ~(MAP_FIXED);
	region_backing_file_path  = backing_file;
}

/*-----------------------------------------------------------------------------
    print_region_info
-----------------------------------------------------------------------------*/
void mmap_region_info::print_region_info(const char* log_prefix, void (*logfunc)(const char* format, ...))
{
	if (!logfunc)
		logfunc = mvee::logf;

	logfunc("%s - " PTRSTR "-" PTRSTR " - %s - %s - %s\n",
			log_prefix,
			region_base_address, region_base_address + region_size,
			region_backing_file_path.c_str(),
			getTextualProtectionFlags(region_prot_flags).c_str(),
			getTextualMapType(region_map_flags).c_str());
}

/*-----------------------------------------------------------------------------
    mmap_table class
-----------------------------------------------------------------------------*/
void mmap_table::init()
{
	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&mmap_lock, &attr);
}

mmap_table::mmap_table()
	: mmap_execve_id(0),
	  thread_group_shutting_down(false)
{
	init();
	mmap_startup_info.resize(mvee::numvariants);
}

mmap_table::mmap_table(const mmap_table& parent)
{
	init();

	mmap_execve_id             = parent.mmap_execve_id;
	mmap_startup_info          = parent.mmap_startup_info;
	thread_group_shutting_down = false;

	active_dangerous_instructions                      = parent.active_dangerous_instructions;
	active_executable_page_with_dangerous_instructions = parent.active_executable_page_with_dangerous_instructions;
	prot_non_exec_map                                  = parent.prot_non_exec_map;
}

mmap_table::~mmap_table()
{}

/*-----------------------------------------------------------------------------
    grab_lock
-----------------------------------------------------------------------------*/
void mmap_table::grab_lock()
{
	pthread_mutex_lock(&mmap_lock);
}

/*-----------------------------------------------------------------------------
    release_lock
-----------------------------------------------------------------------------*/
void mmap_table::release_lock()
{
	pthread_mutex_unlock(&mmap_lock);
}

/*-----------------------------------------------------------------------------
    full_release_lock
-----------------------------------------------------------------------------*/
void mmap_table::full_release_lock()
{
	while (mmap_lock.__data.__owner == syscall(__NR_gettid))
		release_lock();
}
