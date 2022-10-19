/*
 * Cerberus PKU-based Sandbox
 *
 * Check Cerberus/cerberus_ReMon/README.md for licensing terms.
 */

/*
 * This version of MVEE_memory.cpp is entirely based on the
 * process_vm_[readv|writev] system calls added in linux kernel 3.2. Even though
 * these calls perform much better than standard ptrace calls, I still expect
 * them to be much slower than the MVEE ptrace extensions
 */

#include <cstddef>
#include <cstdio>
#include <new>
#include <cstring>
#include "MVEE.h"
#include "MVEE_monitor.h"
#include "MVEE_macros.h"
#include "MVEE_memory.h"

namespace rw
{
/*-----------------------------------------------------------------------------
  mvee_rw_copy_data - copy data from one process to another. Without the
  MVEE ptrace extension, we have to redirect all copies through the monitor
-----------------------------------------------------------------------------*/
	long copy_data(pid_t source_pid, void* source_addr, pid_t dest_pid, void* dest_addr, ssize_t len)
	{
		bool mvee_is_source = false;
		bool mvee_is_dest   = false;

		if (len <= 0)
			return -1;

		if (source_pid == mvee::os_getpid() || 
			source_pid == mvee::os_gettid())
			mvee_is_source = true;

		if (dest_pid == mvee::os_getpid() || 
			dest_pid == mvee::os_gettid())
			mvee_is_dest = true;

		if (mvee_is_source) {
			// monitor to variant copy
			if (!interaction::write_memory(dest_pid, dest_addr, len, source_addr))
				return -1;
		}
		else if (mvee_is_dest) {
			// variant to monitor copy
			if (!interaction::read_memory(source_pid, source_addr, len, dest_addr))
				return -1;
		}
		else {
			// variant to variant copy
			auto buf   = new(std::nothrow) unsigned char[len];
			if (!buf)
				return -1;

			if (!interaction::read_memory(source_pid, source_addr, len, buf) ||
				!interaction::write_memory(dest_pid, dest_addr, len, buf))
			{
				SAFEDELETEARRAY(buf);
				return -1;
			}

			SAFEDELETEARRAY(buf);
		}

		return len;
	}

/*-----------------------------------------------------------------------------
  write_data - write databuf to target variant's address space
-----------------------------------------------------------------------------*/
	bool write_data(pid_t variantpid, void* addr, ssize_t datalength, void* databuf)
	{
		if (!interaction::write_memory(variantpid, addr, datalength, databuf))
			return false;
		return true;
	}

/*-----------------------------------------------------------------------------
  read_data - same as above. This should be pretty fast with the
  stock 3.2+ kernel
-----------------------------------------------------------------------------*/
	unsigned char* read_data(pid_t variantpid, void* addr, ssize_t datalength, int append_zero_byte)
	{
		if (datalength <= 0)
			return nullptr;

		auto buf   = new(std::nothrow) unsigned char[datalength + (append_zero_byte ? 1 : 0)];
		if (!buf)
			return nullptr;

		if (append_zero_byte)
			buf[datalength] = '\0';

		if (!interaction::read_memory(variantpid, addr, datalength, buf)) {
			SAFEDELETEARRAY(buf);
			return nullptr;
		}

		return buf;
	}

/*-----------------------------------------------------------------------------
  read_string - and this is where the stock kernel really sucks...
  If we don't know the size of the string, we have to copy it word
  by word...
-----------------------------------------------------------------------------*/
	std::string read_string(pid_t variantpid, void* addr, ssize_t maxlength)
	{
		if (maxlength != 0) {
			char* tmpstr = (char*)read_data(variantpid, addr, maxlength + 1);
			if (tmpstr) {
				tmpstr[maxlength] = '\0';
				std::string result = tmpstr;
				delete[] tmpstr;
				return result;
			}
		}

		std::string  result;
		int          pos    = 0;
		unsigned int i;

		while (true) {
			long tmp; 
		
			if (!rw::read_primitive<long>(variantpid, (void*) ((unsigned long)addr + (pos++) * sizeof(long)), tmp))
				return "";

			// extract bytes
			for (i = 0; i < sizeof(long); ++i) {
				char c = (char)((tmp >> (i*8)) & 0xFF);
				if (c)
					result += c;
				else
					break;
			}

			if (i < sizeof(long))
				break;
		}

		return result;
	}

/*-----------------------------------------------------------------------------
  read_struct - read directly into buf
-----------------------------------------------------------------------------*/
	bool read_struct(pid_t variantpid, void* addr, ssize_t datalength, void* buf)
	{
		if (datalength <= 0)
			return false;

		if (!interaction::read_memory(variantpid, addr, datalength, buf)) {
			memset(buf, 0, datalength);
			return false;
		}

		return true;
	}
}
