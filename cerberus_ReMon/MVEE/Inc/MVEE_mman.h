/*
 * Cerberus PKU-based Sandbox
 *
 * Check Cerberus/cerberus_ReMon/README.md for licensing terms.
 */

#ifndef MVEE_MMAN_H_INCLUDED
#define MVEE_MMAN_H_INCLUDED

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include <sys/user.h>
#include <pthread.h>
#include <string>
#include <set>
#include <memory>
#include <deque>
#include <vector>
#include <map>
#include <atomic>
#include <unordered_map>
#include "MVEE_build_config.h"
#include "MVEE_private_arch.h"

/*-----------------------------------------------------------------------------
    Class Definitions
-----------------------------------------------------------------------------*/
class mmap_region_info;

// Custom hash function
struct PairHashByFirst
{
public:
	size_t operator()(const std::pair<unsigned long, bool> &pair1) const
	{
		return std::hash<unsigned long>()(pair1.first);
	}
};

// Custom comparator
struct PairEqualByFirst
{
public:
	bool operator()(const std::pair<unsigned long, bool> &pair1, const std::pair<unsigned long, bool> &pair2) const
	{
		if (pair1.first == pair2.first)
			return true;
		else
			return false;
	}
};

//
// Info about an mmap'ed region
//
class mmap_region_info
{
public:
	//
	// mandatory fields
	//
	unsigned long region_base_address;        // start address of the mapping. Can be different for every variant due to ASLR etc.
	unsigned long region_size;                // region size in bytes

	//
	// optional fields used for regions that are backed by files
	//
	unsigned int  region_prot_flags;            // e.g. PROT_EXEC | PROT_READ ...
	unsigned int  region_map_flags;             // e.g. MAP_ANONYMOUS | MAP_PRIVATE ...
	std::string   region_backing_file_path;     // path to the backing file. Kept here because the fd might be closed by the time we unmap
	unsigned int  region_backing_file_offset;   // offset of the region within the backing file (in bytes)

	//
	// Debugging
	//
	void print_region_info(const char* log_prefix, void (*logfunc)(const char* format, ...)=nullptr);

	//
	// Constructor
	//
	mmap_region_info(unsigned long address, unsigned long size, unsigned int prot_flags, std::string backing_file, unsigned int backing_file_offset, unsigned int map_flags);
};

//
// Information about the execve call that created an address space
//
class startup_info
{
public:
	std::string              image;                   // original name of the program we wanted to start
	std::string              serialized_argv;         // serialized program arguments
	std::string              serialized_envp;         // serialized environment variables
	std::deque<std::string>  argv;                    // vectorized program arguments
	std::deque<std::string>  envp;                    // vectorized environment variables
	std::string              interp;                  // interpreter used to start the original program
};

//
// Mmap info table
//
class mmap_table
{
public:
	int         mmap_execve_id;                       // monitorid of the variant that created the table/address space
	std::vector<startup_info>
				mmap_startup_info;                    // information about the execve call used to create this address space
	std::atomic<bool>
				thread_group_shutting_down;           // is this thread group shutting down asynchronously?

	std::unordered_set<std::pair<unsigned long, bool>, PairHashByFirst, PairEqualByFirst>
				active_dangerous_instructions;                      // "active" dangerous instructions that we need to vet
	unsigned long
				active_executable_page_with_dangerous_instructions; // this is needed when we have more than 4 "active" dangerous instructions
	std::unordered_map<unsigned long, unsigned long>
				prot_non_exec_map;                                  // this is needed when we have more than 4 "active" dangerous instructions

	//
	// Initialization functions
	//
	mmap_table                  ();
	mmap_table                  (const mmap_table& parent);
	~mmap_table                 ();

	//
	// Synchronization functions
	//
	void grab_lock                   ();
	void release_lock                ();
	void full_release_lock           ();

private:
	void init();
	pthread_mutex_t mmap_lock;
};

#endif /* MVEE_MMAN_H_INCLUDED */
