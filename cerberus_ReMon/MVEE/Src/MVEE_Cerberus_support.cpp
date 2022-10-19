/*
 * Cerberus PKU-based Sandbox
 *
 * Check Cerberus/cerberus_ReMon/README.md for licensing terms.
 */

// *****************************************************************************
// This file implements the "heart" of Cerberus.
// A lot of memory scanning stuff and other PKU-related goodies are here.
// *****************************************************************************

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include <sys/mman.h>
#include <sys/shm.h>
#include <cstring>
#include <libgen.h>
#include <fstream>
#include <iostream>
#include <cstdio>
#include "MVEE.h"
#include "MVEE_monitor.h"
#include "MVEE_mman.h"
#include "MVEE_macros.h"
#include "MVEE_signals.h"
#include "MVEE_syscalls.h"
#include "MVEE_interaction.h"
#include "MVEE_erim.h"
#include "MVEE_libcver.h"

/*-----------------------------------------------------------------------------
    Static Variable Initialization
-----------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------
   Based on Anjo Vahldiek-Oberwagner's code from https://github.com/vahldiek/erim

   Check if WRPKRU starting at addr is benign
   a) check that it follows the structure of a switch
   b) check that it is whitelisted

   Return: 0 -> not benign
           1 -> benign
-----------------------------------------------------------------------------*/
int monitor::isBenignWRPKRU(uint32_t untrustedPKRU, char* loc)
{
#ifdef	ENABLE_ERIM_POLICY
	uint8_t * addr = uint8ptr(loc);

	addr -= 9; // length of prefix of before WRPKRU

	// test for switch from isolated to app
	if(addr[0] == 0x31 && // first xor opcode
	   addr[1] == 0xc9 && // register ecx xored
	   addr[2] == 0x31 && // second xor opcode
	   addr[3] == 0xd2 && // register edx xored
	   addr[4] == 0xb8 && // mov opcode
	   *((uint32_t*) &addr[5]) == untrustedPKRU && // new PKRU value is application
	   addr[5] == addr[13] && // first bit of pkrus in mov and cmp
	   addr[6] == addr[14] && // second bit of pkrus in mov and cmp
	   addr[7] == addr[15] && // third bit of pkrus in mov and cmp
	   addr[8] == addr[16] && // fourth bit of pkrus in mov and cmp
	   erim_isWRPKRU(&addr[9]) && //wpkru sequence
	   addr[12] == 0x3d && // cmp opcode
	   (
			   (addr[17] == 0x75 // jmp opcode gcc (short opcode)
				&& (0xff - addr[18]) == 0x12) // addr for short jmp code
			   ||
			   (addr[17] == 0x0f && addr[18] == 0x85 &&  // jmp opcode clang (long opcode)
				(0xffffffff - *((uint32_t*)&addr[19])) == 0x16) // addr clalc
	   ))
	{
		return 1;
	}
	// might be a switch to isolation
	else if(addr[0] == 0x31 && // first xor opcode
			  addr[1] == 0xc9 && // register ecx xored
			  addr[2] == 0x31 && // second xor opcode
			  addr[3] == 0xd2 && // register edx xored
			  addr[4] == 0xb8 && // mov opcode
			  *((uint32_t*) &addr[5]) == ERIM_TRUSTED_PKRU && // new PKRU value is application
			  // addr[5] == addr[13] && // first bit of pkrus in mov and cmp
			  // addr[6] == addr[14] && // second bit of pkrus in mov and cmp
			  // addr[7] == addr[15] && // third bit of pkrus in mov and cmp
			  // addr[8] == addr[16] && // fourth bit of pkrus in mov and cmp
			  erim_isWRPKRU(&addr[9])) { //wpkru sequence

		return 1;
	}
	// if it is not one of the gates
	else { // non benign WRPKRU found
		return 0;
	}
#else
	return 0;
#endif
}

/*-----------------------------------------------------------------------------
    Based on Anjo Vahldiek-Oberwagner's code from https://github.com/vahldiek/erim

    Scan for WRPKRU/XRSTOR sequence in memory segment
-----------------------------------------------------------------------------*/
unsigned long monitor::erim_scanMemForWRPKRUXRSTOR(char* mem_start, unsigned long length)
{
	auto     ptr           = (uint8_t*)mem_start;
	unsigned int it        = 0;
	unsigned long ret = 0;
	for(it = 0; it < length; it++) {
		if(erim_isWRPKRU(&ptr[it])) {
			ret = it;
			break;
		}
		if(erim_isXRSTOR(&ptr[it])) {
			ret = it;
			break;
		}
	}
	return ret;
}

/*-----------------------------------------------------------------------------
    Based on Anjo Vahldiek-Oberwagner's code from https://github.com/vahldiek/erim

    Returns a vector with the offsets of the dangerous instructions or an empty one
    It is up to the programmer to do something with them.
    Bool is set to true if it is an XRSTOR occurrence and false otherwise.
-----------------------------------------------------------------------------*/
std::unordered_set<std::pair<unsigned long, bool>, PairHashByFirst, PairEqualByFirst> monitor::erim_memScanRegion(uint32_t untrustedPKRU, char* origstart, unsigned long origlength, const char* pathname)
{
	// bool set to true if it is XRSTOR instruction
	// otherwise false
	std::unordered_set<std::pair<unsigned long, bool>, PairHashByFirst, PairEqualByFirst> offsets;

	unsigned long    skip  = 0;
	char*            start = origstart;
	unsigned long   length = origlength;

	// iterate over every byte and check for WRPKRU/XRSTOR sequence
	while (length > 0) {
		// scan for WRPKRU/XRSTOR
		unsigned long long found = erim_scanMemForWRPKRUXRSTOR(start, length);

		if (found) {// found a sequence at found
			debugf("%s found WRPKRU/XRSTOR at offset %lld\n", mvee::active_monitor->call_get_variant_pidstr().c_str(), skip + found);

			// check for non benign WRPKRU or XRSTOR (we treat all XRSTOR instructions equally)
			if((found < 9 || /* cannot be benign due to prefix */ !isBenignWRPKRU(untrustedPKRU, start + found))) {
				auto tmp_ptr = (uint8_t*)origstart;
				if (erim_isWRPKRU(&tmp_ptr[skip + found])) {
					debugf("%s found non benign WRPKRU at offset in library %lld :: library name %s\n",
						   mvee::active_monitor->call_get_variant_pidstr().c_str(), skip + found, pathname);
					offsets.insert(std::make_pair((skip + found), false));
				}
				else if (erim_isXRSTOR(&tmp_ptr[skip + found])) {
					char hexstr[7]; // hex representation of the XRSTOR instruction
					sprintf(&hexstr[0], "%02X", tmp_ptr[skip + found]);
					sprintf(&hexstr[2], "%02X", tmp_ptr[skip + found + 1]);
					sprintf(&hexstr[4], "%02X", tmp_ptr[skip + found + 2]);
					hexstr[6] = '\0';

					debugf("%s found potentially non benign XRSTOR (%s) at offset in library %lld :: library name %s - CHECKING ...\n",
						   mvee::active_monitor->call_get_variant_pidstr().c_str(), hexstr, skip + found, pathname);
// We vet only specific XRSTOR instructions for more info see MVEE_build_config.h
#if defined(MVEE_AVOID_VETTING_EXPLICIT_XRSTOR_IN_LIBC_AND_LD)
					// According to https://man7.org/linux/man-pages/man2/mmap.2.html
					// mmap returns page-aligned memory pointers (consequently they are also 8-byte aligned)
					// So we just need to check if the offset is 8-byte aligned in order to check if it will
					// be mapped in an 8-byte aligned virtual address
					std::string path_to_patched_binaries = mvee::os_get_mvee_root_dir() + "/patched_binaries/libc/amd64/" + LIBC_VER;
					if ((skip + found) % 8 == 0 &&
						((std::string(pathname).find(path_to_patched_binaries + "/" + "ld.so") != std::string::npos) ||
						 (std::string(pathname).find(path_to_patched_binaries + "/" + "libc.so") != std::string::npos))) {

						debugf("%s XRSTOR at offset in library %lld :: library name %s - It is benign!\n",
							   mvee::active_monitor->call_get_variant_pidstr().c_str(), skip + found, pathname);
					}
					else {
						debugf("%s XRSTOR at offset in library %lld :: library name %s - It is non benign!\n",
							   mvee::active_monitor->call_get_variant_pidstr().c_str(), skip + found, pathname);
						offsets.insert(std::make_pair((skip + found), true));
					}
// We don't vet XRSTOR instructions (we may want to do that if for example we binary rewrite all the dangerous XRSTOR instructions to their safe equivalent versions
#elif defined(MVEE_AVOID_VETTING_XRSTOR)
					// Do nothing here
						debugf("%s XRSTOR at offset in library %lld :: library name %s - It doesn't matter if it is non benign or not. We don't vet any XRSTOR instructions!\n",
							   mvee::active_monitor->call_get_variant_pidstr().c_str(), skip + found, pathname);
// We vet all XRSTOR instructions
#else
						debugf("%s XRSTOR at offset in library %lld :: library name %s - It doesn't matter if it is non benign or not. We vet all XRSTOR instructions!\n",
							   mvee::active_monitor->call_get_variant_pidstr().c_str(), skip + found, pathname);
						offsets.insert(std::make_pair((skip + found), true));
#endif
				}
			}

			length -= (found + 3);
			start  += (found + 3);
			skip   += (found + 3);
			// continue if length > 0
		}
		else { // (!found)
			length = 0; // break loop
		}
	} // while (length > 0)

	return offsets;
}

/*-----------------------------------------------------------------------------
    pmparser_parse
-----------------------------------------------------------------------------*/
procmaps_iterator* monitor::pmparser_parse(int pid)
{
	auto maps_it = new(std::nothrow) procmaps_iterator();
	char maps_path[500];
	if(pid >= 0 )
		sprintf(maps_path,"/proc/%d/maps",pid);
	else
		sprintf(maps_path,"/proc/self/maps");

	FILE* file = fopen(maps_path,"r");
	if(!file) {
		fprintf(stderr,"pmparser : cannot open the memory maps, %s\n", strerror(errno));
		return nullptr;
	}

	int  ind = 0;
	char buf[PROCMAPS_LINE_MAX_LENGTH];
	//int  c;

	procmaps_struct* list_maps    = nullptr;
	procmaps_struct* tmp;
	procmaps_struct* current_node = list_maps;
	char addr1[20], addr2[20], perm[8], offset[20], dev[10], inode[30], pathname[PATH_MAX];

	while(!feof(file)) {
		fgets(buf, PROCMAPS_LINE_MAX_LENGTH, file);
		//allocate a node
		tmp = new(std::nothrow) procmaps_struct();
		//fill the node
		_pmparser_split_line(buf, addr1, addr2, perm, offset, dev, inode, pathname);
		//printf("#%s",buf);
		//printf("%s-%s %s %s %s %s\t%s\n",addr1,addr2,perm,offset,dev,inode,pathname);
		//addr_start & addr_end
		//unsigned long l_addr_start;
		sscanf(addr1, "%lx", (long unsigned *)&tmp->addr_start);
		sscanf(addr2, "%lx", (long unsigned *)&tmp->addr_end);
		//size
		tmp->length = (unsigned long)((unsigned long)tmp->addr_end - (unsigned long)tmp->addr_start);
		//perm
		strcpy(tmp->perm, perm);
		tmp->is_r = (perm[0]=='r');
		tmp->is_w = (perm[1]=='w');
		tmp->is_x = (perm[2]=='x');
		tmp->is_p = (perm[3]=='p');

		//offset
		sscanf(offset, "%lx", &tmp->offset );
		//device
		strcpy(tmp->dev, dev);
		//inode
		tmp->inode = atoi(inode);
		//pathname
		strcpy(tmp->pathname, pathname);
		tmp->next  = nullptr;
		//attach the node
		if(ind == 0) {
			list_maps       = tmp;
			list_maps->next = nullptr;
			current_node    = list_maps;
		}
		current_node->next  = tmp;
		current_node        = tmp;
		ind++;
		//printf("%s",buf);
	}

	//close file
	fclose(file);

	maps_it->head           = list_maps;
	maps_it->current        = list_maps;

	return maps_it;
}

/*-----------------------------------------------------------------------------
    pmparser_next
-----------------------------------------------------------------------------*/
procmaps_struct* monitor::pmparser_next(procmaps_iterator* p_procmaps_it)
{
	if(p_procmaps_it->current == nullptr)
		return nullptr;

	procmaps_struct* p_current = p_procmaps_it->current;
	p_procmaps_it->current     = p_procmaps_it->current->next;

	return p_current;
	/*
	if(g_current==NULL){
		g_current=g_last_head;
	}else
		g_current=g_current->next;

	return g_current;
	*/
}

/*-----------------------------------------------------------------------------
    pmparser_free
-----------------------------------------------------------------------------*/
void monitor::pmparser_free(procmaps_iterator* p_procmaps_it)
{
	procmaps_struct* maps_list = p_procmaps_it->head;
	if(maps_list == nullptr)
		return;

	procmaps_struct* act       = maps_list;
	procmaps_struct* nxt       = act->next;

	while(act != nullptr) {
		SAFEDELETE(act);
		act = nxt;
		if(nxt != nullptr)
			nxt = nxt->next;
	}
}

/*-----------------------------------------------------------------------------
    _pmparser_split_line
-----------------------------------------------------------------------------*/
void monitor::_pmparser_split_line(char* buf, char* addr1, char* addr2, char* perm, char* offset, char* device, char* inode, char* pathname)
{
	//
	int orig = 0;
	int i    = 0;
	//addr1
	while(buf[i] != '-') {
		addr1[i - orig] = buf[i];
		i++;
	}
	addr1[i] = '\0';
	i++;

	//addr2
	orig = i;
	while(buf[i] != '\t' && buf[i] != ' ') {
		addr2[i - orig] = buf[i];
		i++;
	}
	addr2[i - orig] = '\0';

	//perm
	while(buf[i] == '\t' || buf[i] == ' ')
		i++;
	orig = i;
	while(buf[i] != '\t' && buf[i] != ' ') {
		perm[i - orig] = buf[i];
		i++;
	}
	perm[i - orig] = '\0';

	//offset
	while(buf[i] == '\t' || buf[i] == ' ')
		i++;
	orig = i;
	while(buf[i] != '\t' && buf[i] != ' ') {
		offset[i - orig] = buf[i];
		i++;
	}
	offset[i - orig] = '\0';

	//dev
	while(buf[i] == '\t' || buf[i] == ' ')
		i++;
	orig = i;
	while(buf[i] != '\t' && buf[i] != ' ') {
		device[i - orig] = buf[i];
		i++;
	}
	device[i - orig] = '\0';

	//inode
	while(buf[i] == '\t' || buf[i] == ' ')
		i++;
	orig = i;
	while(buf[i] != '\t' && buf[i] != ' ') {
		inode[i - orig] = buf[i];
		i++;
	}
	inode[i - orig] = '\0';

	//pathname
	pathname[0] = '\0';
	while(buf[i] == '\t' || buf[i] == ' ')
		i++;
	orig = i;
	while(buf[i] != '\t' && buf[i] != ' ' && buf[i] != '\n') {
		pathname[i - orig] = buf[i];
		i++;
	}
	pathname[i - orig] = '\0';
}

/*-----------------------------------------------------------------------------
    pmparser_print
-----------------------------------------------------------------------------*/
void monitor::pmparser_print(procmaps_struct* map, int order, bool print_only_executable_areas)
{
	procmaps_struct* tmp = map;
	int               id = 0;

	if(order < 0)
		order = -1;

	while (tmp != nullptr) {
		//(unsigned long) tmp->addr_start;
		if (order == id || order == -1) {
			if (!print_only_executable_areas || tmp->is_x) {
				debugf("Backed by:\t%s\n", strlen(tmp->pathname) == 0 ? "[anonym*]" : tmp->pathname);
				debugf("Range:\t\t%p-%p\n", tmp->addr_start, tmp->addr_end);
				debugf("Length:\t\t%ld\n", tmp->length);
				debugf("Offset:\t\t%ld\n", tmp->offset);
				debugf("Permissions:\t%s\n", tmp->perm);
				debugf("Inode:\t\t%d\n", tmp->inode);
				debugf("Device:\t\t%s\n", tmp->dev);
			}
		}

		if (order != -1 && id > order) {
			tmp = nullptr;
		}
		else if (order == -1) {
			debugf("#################################\n");
			tmp = tmp->next;
		}
		else {
			tmp = tmp->next;
		}

		id++;
	}
}

/*-----------------------------------------------------------------------------
    is_region_included
-----------------------------------------------------------------------------*/
bool monitor::is_region_included(void* start_region, size_t len1, void* addr, size_t len2)
{
	if ((unsigned long)start_region >= (unsigned long)addr && (unsigned long)start_region < (unsigned long)addr + len2)
		return true;
	if((unsigned long)start_region < (unsigned long)addr && (unsigned long)start_region + len1 >= (unsigned long)addr)
		return true;
	return false;
}

/*-----------------------------------------------------------------------------
    pmparser_get_vdso_dangerous_instructions
-----------------------------------------------------------------------------*/
std::unordered_set<std::pair<unsigned long, bool>, PairHashByFirst, PairEqualByFirst> monitor::pmparser_get_vdso_dangerous_instructions()
{
	debugf("### pmparser_get_vdso_dangerous_instructions start ###\n");

	// bool set to true if it is XRSTOR instruction
	// otherwise false
	std::unordered_set<std::pair<unsigned long, bool>, PairHashByFirst, PairEqualByFirst> addresses_to_vet;
	procmaps_iterator* maps = pmparser_parse(mvee::active_monitor->variants[0].variantpid);
	if (maps == nullptr)
		warnf("[map]: cannot parse the memory map of %d\n", mvee::active_monitor->variants[0].variantpid);

	//iterate over areas
	procmaps_struct* maps_tmp;
	while ((maps_tmp = pmparser_next(maps)) != nullptr) {
		if ((std::string(maps_tmp->pathname).find("[vdso]") != std::string::npos) && maps_tmp->is_x) {
			debugf("Backed by:\t%s\n", strlen(maps_tmp->pathname) == 0 ? "[anonym*]" : maps_tmp->pathname);
			debugf("Range:\t\t%p-%p\n", maps_tmp->addr_start, maps_tmp->addr_end);
			debugf("Length:\t\t%ld\n", maps_tmp->length);
			debugf("Offset:\t\t%ld\n", maps_tmp->offset);
			debugf("Permissions:\t%s\n", maps_tmp->perm);

			char* buf = new(std::nothrow) char[maps_tmp->length];
			if (!interaction::read_memory(mvee::active_monitor->variants[0].variantpid, maps_tmp->addr_start, maps_tmp->length, buf))
				throw RwMemFailure(0, "Failed to read contents of vdso that is mapped in the variant\n");

			auto offsets = erim_memScanRegion(ERIM_UNTRUSTED_PKRU, buf, maps_tmp->length, maps_tmp->pathname);
			for (const auto& offset: offsets) {
				unsigned long address_of_dangerous_instruction = (unsigned long)maps_tmp->addr_start + offset.first;
				addresses_to_vet.insert(std::make_pair(address_of_dangerous_instruction, offset.second));
			}

			auto tmp_addresses_to_vet = pmparser_get_partial_dangerous_instructions_of_a_region(maps,
																								buf, maps_tmp->length,
																								maps_tmp->addr_start,
																								true,
																								ONLY_EXEC,
																								ONLY_EXEC);
			for (const auto& tmp_address_to_vet: tmp_addresses_to_vet)
				addresses_to_vet.insert(std::make_pair(tmp_address_to_vet.first, tmp_address_to_vet.second));

			SAFEDELETEARRAY(buf);
		}
	}

	// mandatory: should free the list
	pmparser_free(maps);

	// mandatory: should free the iterator
	SAFEDELETE(maps);

	debugf("### pmparser_get_vdso_dangerous_instructions end ###\n");

	return addresses_to_vet;
}

/*-----------------------------------------------------------------------------
    get_ld_loader_bounds
-----------------------------------------------------------------------------*/
bool monitor::pmparser_get_ld_loader_bounds(unsigned long& loader_base, unsigned long& loader_size)
{
	debugf("### pmparser_get_ld_loader_bounds start ###\n");

	unsigned long tmp_loader_base        = MVEE_LD_LOADER_BASE;
	unsigned long tmp_loader_size        = 0;
	bool          found_ld_loader_bounds = false;

	procmaps_iterator* maps = pmparser_parse(mvee::active_monitor->variants[0].variantpid);
	if (maps == nullptr)
		warnf("[map]: cannot parse the memory map of %d\n", mvee::active_monitor->variants[0].variantpid);

	//iterate over areas
	procmaps_struct* maps_tmp;
	while ((maps_tmp = pmparser_next(maps)) != nullptr) {
		if (std::string(maps_tmp->pathname).find(MVEE_LD_LOADER_NAME) != std::string::npos) {
			debugf("Backed by:\t%s\n", strlen(maps_tmp->pathname) == 0 ? "[anonym*]" : maps_tmp->pathname);
			debugf("Range:\t\t%p-%p\n", maps_tmp->addr_start, maps_tmp->addr_end);
			debugf("Length:\t\t%ld\n", maps_tmp->length);
			debugf("Offset:\t\t%ld\n", maps_tmp->offset);
			debugf("Permissions:\t%s\n", maps_tmp->perm);

			tmp_loader_base = MIN((unsigned long)maps_tmp->addr_start, tmp_loader_base);
			tmp_loader_size = MAX(tmp_loader_size, (unsigned long)maps_tmp->addr_end - tmp_loader_base);

			found_ld_loader_bounds = true;
		}
	}

	// mandatory: should free the list
	pmparser_free(maps);

	// mandatory: should free the iterator
	SAFEDELETE(maps);

	if (found_ld_loader_bounds) {
		loader_base = tmp_loader_base;
		loader_size = tmp_loader_size;
	}

	debugf("### pmparser_get_ld_loader_bounds end ###\n");

	return found_ld_loader_bounds;
}

/*-----------------------------------------------------------------------------
    pmparser_get_region_info
-----------------------------------------------------------------------------*/
mmap_region_info* monitor::pmparser_get_region_info(unsigned long address)
{
	debugf("### pmparser_get_region_info start ###\n");

	mmap_region_info* region = nullptr;

	procmaps_iterator* maps = pmparser_parse(mvee::active_monitor->variants[0].variantpid);
	if (maps == nullptr)
		warnf("[map]: cannot parse the memory map of %d\n", mvee::active_monitor->variants[0].variantpid);

	//iterate over areas
	procmaps_struct* maps_tmp;
	while ((maps_tmp = pmparser_next(maps)) != nullptr) {
		if ((unsigned long)maps_tmp->addr_start <= address && address < (unsigned long)maps_tmp->addr_end) {
			debugf("Backed by:\t%s\n", strlen(maps_tmp->pathname) == 0 ? "[anonym*]" : maps_tmp->pathname);
			debugf("Range:\t\t%p-%p\n", maps_tmp->addr_start, maps_tmp->addr_end);
			debugf("Length:\t\t%ld\n", maps_tmp->length);
			debugf("Offset:\t\t%ld\n", maps_tmp->offset);
			debugf("Permissions:\t%s\n", maps_tmp->perm);

			int prot_flags = 0;
			if (maps_tmp->is_x)
				prot_flags |= PROT_EXEC;
			if (maps_tmp->is_r)
				prot_flags |= PROT_READ;
			if (maps_tmp->is_w)
				prot_flags |= PROT_WRITE;

			region = new mmap_region_info((unsigned long)maps_tmp->addr_start, maps_tmp->length, prot_flags, strlen(maps_tmp->pathname) == 0 ? "[anonym*]" : maps_tmp->pathname, maps_tmp->offset, 0);
			break;
		}
	}

	// mandatory: should free the list
	pmparser_free(maps);

	// mandatory: should free the iterator
	SAFEDELETE(maps);

	debugf("### pmparser_get_region_info end ###\n");

	return region;
}


/*-----------------------------------------------------------------------------
    pmparser_get_page
-----------------------------------------------------------------------------*/
char* monitor::pmparser_get_page(procmaps_iterator* p_procmaps_it, void* addr, ScanType type)
{
	debugf("### pmparser_get_page start ###\n");
	debugf("Getting executable page at address %p\n", (void*)addr);

	char* page        = nullptr;
	procmaps_iterator* maps;
	if (p_procmaps_it) {
		maps          = new(std::nothrow) procmaps_iterator();
		maps->head    = p_procmaps_it->head;
		maps->current = p_procmaps_it->current;
	}
	else {
		maps          = pmparser_parse(mvee::active_monitor->variants[0].variantpid);
	}

	if (maps == nullptr)
		warnf("[map]: cannot parse the memory map of %d\n", mvee::active_monitor->variants[0].variantpid);

	//iterate over areas
	procmaps_struct* maps_tmp;
	while ((maps_tmp = pmparser_next(maps)) != nullptr) {
		// We cannot access [vvar] and [vsyscall] from ptrace:
		//    https://twitter.com/moyix/status/951577738422472704
		//    http://lkml.iu.edu/hypermail/linux/kernel/1503.1/03733.html
		//    https://gist.github.com/moyix/01aa2682d70f6283ccbb7c9c5d44b65f
		if (std::string(maps_tmp->pathname) != "[vvar]" && std::string(maps_tmp->pathname) != "[vsyscall]"
			// what do we want?
			&& (type == EVERYTHING || (type == ONLY_EXEC && maps_tmp->is_x) || (type == ONLY_NON_EXEC && !maps_tmp->is_x))
			// is the requested page in this region?
			&& (maps_tmp->addr_start <= addr && addr < maps_tmp->addr_end))
		{
			debugf("Backed by:\t%s\n", strlen(maps_tmp->pathname) == 0 ? "[anonym*]" : maps_tmp->pathname);
			debugf("Range:\t\t%p-%p\n", maps_tmp->addr_start, maps_tmp->addr_end);
			debugf("Length:\t\t%ld\n", maps_tmp->length);
			debugf("Offset:\t\t%ld\n", maps_tmp->offset);
			debugf("Permissions:\t%s\n", maps_tmp->perm);

			struct stat sb{};
			unsigned long correct_len;

			// Search for the word "beyond" in the following links to understand what is happening here:
			//   https://docs.oracle.com/cd/E88353_01/html/E37841/mmap-2.html
			//   https://www.ibm.com/support/knowledgecenter/ssw_ibm_i_74/apis/mmap.htm
			//   https://man7.org/linux/man-pages/man2/mmap.2.html
			//
			// Any reference to addresses beyond the end of the object, however, will result in the delivery of a SIGBUS or SIGSEGV signal
			// !!! This is important !!!
			if (stat(maps_tmp->pathname, &sb) == 0 && sb.st_size > 0) {
				if (sb.st_size > maps_tmp->offset)
					correct_len = MIN(sb.st_size - (unsigned long)maps_tmp->offset, PAGE_SIZE);
				else // yeap we even find cases like that
					goto OUT;
			}
			// this either a special file or an anonymous region
			else {
				correct_len = PAGE_SIZE;
			}

			char* buf = new(std::nothrow) char[correct_len];
			// if the region is readable we can use process_vm_readv
			if (maps_tmp->is_r || maps_tmp->is_x) {
				if (!interaction::read_memory(mvee::active_monitor->variants[0].variantpid, (void*)addr, correct_len, buf))
					throw RwMemFailure(0, "Process_vm_readv failed to read contents of area that is mapped in the variant\n");
			}
			// otherwise just use ptrace
			else {
				if (!interaction::read_memory_ptrace(mvee::active_monitor->variants[0].variantpid, (void*)addr, correct_len, buf))
					throw RwMemFailure(0, "Ptrace failed to read contents of area that is mapped in the variant\n");
			}

			page = new(std::nothrow) char[PAGE_SIZE];
			std::memset(page, 0, PAGE_SIZE); // non accessible bytes are set to 0
			std::memcpy(page, buf, correct_len);
			// debugf("Page:\n%s\n", mvee::log_do_hex_dump(page, PAGE_SIZE).c_str());

			SAFEDELETEARRAY(buf);
			break;
		}
	}

OUT:
	if (!p_procmaps_it) {
		// mandatory: should free the list
		pmparser_free(maps);
	}

	// mandatory: should free the iterator
	SAFEDELETE(maps);

	debugf("### pmparser_get_page end ###\n");

	return page;
}

/*-----------------------------------------------------------------------------
    pmparser_get_partial_dangerous_instructions_of_a_region
-----------------------------------------------------------------------------*/
std::unordered_set<std::pair<unsigned long, bool>, PairHashByFirst, PairEqualByFirst> monitor::pmparser_get_partial_dangerous_instructions_of_a_region
(
	procmaps_iterator* p_procmaps_it,
	char* buf, size_t len,
	void* addr,
	bool check_next_page,
	ScanType previous_type,
	ScanType next_type
)
{
	debugf("### pmparser_get_partial_dangerous_instructions_of_a_region start ###\n");

	std::unordered_set<std::pair<unsigned long, bool>, PairHashByFirst, PairEqualByFirst> addresses_to_vet;

	char* prevpage = nullptr;
	char* nextpage = nullptr;

	// check to ensure that the last bytes of the last page of this region are accessible or a SIGBUS or SIGSEGV signal would be triggered
	// if the last bytes of this region are not accessible, we do not need to check the following page.
	/* check next page */
	if (check_next_page) {
		// CASE 1: (xrst)or
		if (*(uint16_t*)(buf + len - 2) == XRST) {
			nextpage = pmparser_get_page(p_procmaps_it, (void*)((unsigned long)addr + len), next_type);
			if (nextpage && erim_isOR(nextpage)) {
				debugf("Dangerous partial dangerous instruction \"xrst\" at the end of the mapped region.\n");
				debugf("Dangerous partial dangerous instruction \"or\" at the start of the next page.\n");
				addresses_to_vet.insert(std::make_pair((unsigned long)addr + len - 2, true));
			}
		}
		// CASE 2: (wrpk)ru
		else if (*(uint16_t*)(buf + len - 2) == WRPK) {
			nextpage = pmparser_get_page(p_procmaps_it, (void*)((unsigned long)addr + len), next_type);
			if (nextpage && (unsigned char)nextpage[0] == RU) {
				debugf("Dangerous partial dangerous instruction \"wrpk\" at the end of the mapped region.\n");
				debugf("Dangerous partial dangerous instruction \"ru\" at the start of the next page.\n");
				addresses_to_vet.insert(std::make_pair((unsigned long)addr + len - 2, false));
			}
		}
		// CASE 3: (xr)stor or CASE 4: (wr)pkru (XR and WR have the same value)
		else if ((unsigned char)buf[len - 1] == (XR | WR)) {
			nextpage = pmparser_get_page(p_procmaps_it, (void*)((unsigned long)addr + len), next_type);
			if (nextpage) {
				if ((unsigned char)nextpage[0] == ST && erim_isOR(nextpage + 1)) {
					debugf("Dangerous partial dangerous instruction \"xr\" at the end of the mapped region.\n");
					debugf("Dangerous partial dangerous instruction \"stor\" at the start of the next page.\n");
					addresses_to_vet.insert(std::make_pair((unsigned long)addr + len - 1, true));
				}
				else if (*(uint16_t*)nextpage == PKRU) {
					debugf("Dangerous partial dangerous instruction \"wr\" at the end of the mapped region.\n");
					debugf("Dangerous partial dangerous instruction \"pkru\" at the start of the next page.\n");
					addresses_to_vet.insert(std::make_pair((unsigned long)addr + len - 1, false));
				}
			}
		}
	}

	/* check previous page */
	// CASE 5: xr(stor) ... this always needs to be before CASE 6 since erim_isOR(buf) includes (unsigned char)buf[0] == ST check
	if ((unsigned char)buf[0] == ST && erim_isOR(buf + 1)) {
		prevpage = pmparser_get_page(p_procmaps_it, (void*)((unsigned long)addr - PAGE_SIZE), previous_type);
		if (prevpage && prevpage[PAGE_SIZE - 1] == XR) {
			debugf("Dangerous partial dangerous instruction \"stor\" at the start of the mapped region.\n");
			debugf("Dangerous partial dangerous instruction \"xr\" at the end of the previous page.\n");
			addresses_to_vet.insert(std::make_pair((unsigned long)addr - 1, true));
		}
	}
	// CASE 6: xrst(or)
	else if (erim_isOR(buf)) {
		prevpage = pmparser_get_page(p_procmaps_it, (void*)((unsigned long)addr - PAGE_SIZE), previous_type);
		if (prevpage && *(uint16_t*)(prevpage + PAGE_SIZE - 2) == XRST) {
			debugf("Dangerous partial dangerous instruction \"or\" at the start of the mapped region.\n");
			debugf("Dangerous partial dangerous instruction \"xrst\" at the end of the previous page.\n");
			addresses_to_vet.insert(std::make_pair((unsigned long)addr - 2, true));
		}
	}
	// CASE 7: wrpk(ru)
	else if ((unsigned char)buf[0] == RU) {
		prevpage = pmparser_get_page(p_procmaps_it, (void*)((unsigned long)addr - PAGE_SIZE), previous_type);
		if (prevpage && *(uint16_t*)(prevpage + PAGE_SIZE - 2) == WRPK) {
			debugf("Dangerous partial dangerous instruction \"ru\" at the start of the mapped region.\n");
			debugf("Dangerous partial dangerous instruction \"wrpk\" at the end of the previous page.\n");
			addresses_to_vet.insert(std::make_pair((unsigned long)addr - 2, false));
		}
	}
	// CASE 8: wr(pkru)
	else if (*(uint16_t*)buf== PKRU) {
		prevpage = pmparser_get_page(p_procmaps_it, (void*)((unsigned long)addr - PAGE_SIZE), previous_type);
		if (prevpage && prevpage[PAGE_SIZE - 1] == WR) {
			debugf("Dangerous partial dangerous instruction \"pkru\" at the start of the mapped region.\n");
			debugf("Dangerous partial dangerous instruction \"wr\" at the end of the previous page.\n");
			addresses_to_vet.insert(std::make_pair((unsigned long)addr - 1, false));
		}
	}

	SAFEDELETE(prevpage);
	SAFEDELETE(nextpage);

	debugf("### pmparser_get_partial_dangerous_instructions_of_a_region end ###\n");

	return addresses_to_vet;
}

/*-----------------------------------------------------------------------------
    pmparser_get_partial_dangerous_instructions
-----------------------------------------------------------------------------*/
std::unordered_set<std::pair<unsigned long, bool>, PairHashByFirst, PairEqualByFirst> monitor::pmparser_get_partial_dangerous_instructions
(
	void* addr, size_t len,
	ScanType region_type,
	ScanType pn_type
)
{
	debugf("### pmparser_get_partial_dangerous_instructions start ###\n");

	len = ROUND_UP(len, PAGE_SIZE);

	// bool set to true if it is XRSTOR instruction
	// otherwise false
	std::unordered_set<std::pair<unsigned long, bool>, PairHashByFirst, PairEqualByFirst> addresses_to_vet;
	procmaps_iterator* maps = pmparser_parse(mvee::active_monitor->variants[0].variantpid);
	if (maps == nullptr)
		warnf("[map]: cannot parse the memory map of %d\n", mvee::active_monitor->variants[0].variantpid);

	//iterate over areas
	procmaps_struct* maps_tmp;
	while ((maps_tmp = pmparser_next(maps)) != nullptr) {
		// We cannot access [vvar] and [vsyscall] from ptrace:
		//    https://twitter.com/moyix/status/951577738422472704
		//    http://lkml.iu.edu/hypermail/linux/kernel/1503.1/03733.html
		//    https://gist.github.com/moyix/01aa2682d70f6283ccbb7c9c5d44b65f
		if (std::string(maps_tmp->pathname) != "[vvar]" && std::string(maps_tmp->pathname) != "[vsyscall]"
			// what do we want?
			&& (region_type == EVERYTHING || (region_type == ONLY_EXEC && maps_tmp->is_x) || (region_type == ONLY_NON_EXEC && !maps_tmp->is_x))
			// is the region included in this address range?
			&& is_region_included(maps_tmp->addr_start, maps_tmp->length, addr, len))
		{
			debugf("Backed by:\t%s\n", strlen(maps_tmp->pathname) == 0 ? "[anonym*]" : maps_tmp->pathname);
			debugf("Range:\t\t%p-%p\n", maps_tmp->addr_start, maps_tmp->addr_end);
			debugf("Length:\t\t%ld\n", maps_tmp->length);
			debugf("Offset:\t\t%ld\n", maps_tmp->offset);
			debugf("Permissions:\t%s\n", maps_tmp->perm);

			struct stat sb{};
			unsigned long correct_len;

			// Search for the word "beyond" in the following links to understand what is happening here:
			//   https://docs.oracle.com/cd/E88353_01/html/E37841/mmap-2.html
			//   https://www.ibm.com/support/knowledgecenter/ssw_ibm_i_74/apis/mmap.htm
			//   https://man7.org/linux/man-pages/man2/mmap.2.html
			//
			// Any reference to addresses beyond the end of the object, however, will result in the delivery of a SIGBUS or SIGSEGV signal
			// !!! This is important !!!
			if (stat(maps_tmp->pathname, &sb) == 0 && sb.st_size > 0) {
				if (sb.st_size > maps_tmp->offset)
					correct_len = MIN(sb.st_size - (unsigned long)maps_tmp->offset, maps_tmp->length);
				else // yeap we even find cases like that
					continue;
			}
			// this either a special file or an anonymous region
			else {
				correct_len = maps_tmp->length;
			}

			char* buf = new(std::nothrow) char[correct_len];
			// if the region is readable we can use process_vm_readv
			if (maps_tmp->is_r || maps_tmp->is_x) {
				if (!interaction::read_memory(mvee::active_monitor->variants[0].variantpid, maps_tmp->addr_start, correct_len, buf))
					throw RwMemFailure(0, "Process_vm_readv failed to read contents of area that is mapped in the variant\n");
			}
			// otherwise use ptrace
			else {
				if (!interaction::read_memory_ptrace(mvee::active_monitor->variants[0].variantpid, maps_tmp->addr_start,  correct_len, buf)) {
					throw RwMemFailure(0, "Ptrace failed to read contents of area that is mapped in the variantn");
				}
			}

			ScanType tmp_previous_type = pn_type;
			ScanType tmp_next_type     = pn_type;
			if (maps_tmp->addr_start == addr)
				tmp_previous_type  = ONLY_EXEC;
			if ((unsigned long)maps_tmp->addr_end == (unsigned long)addr + len)
				tmp_next_type      = ONLY_EXEC;

			auto tmp_addresses_to_vet = pmparser_get_partial_dangerous_instructions_of_a_region(maps,
																								buf, correct_len,
																								maps_tmp->addr_start,
																								correct_len == maps_tmp->length,
																								tmp_previous_type,
																								tmp_next_type);
			for (const auto& tmp_address_to_vet: tmp_addresses_to_vet) {
				if ((unsigned long)addr - 2 <= tmp_address_to_vet.first && tmp_address_to_vet.first < (unsigned long)addr + len)
					addresses_to_vet.insert(std::make_pair(tmp_address_to_vet.first, tmp_address_to_vet.second));
			}

			SAFEDELETEARRAY(buf);
		}
	}

	// mandatory: should free the list
	pmparser_free(maps);

	// mandatory: should free the iterator
	SAFEDELETE(maps);

	debugf("### pmparser_get_partial_dangerous_instructions end ###\n");

	return addresses_to_vet;
}

/*-----------------------------------------------------------------------------
    pmparser_get_dangerous_instructions_mprotect
-----------------------------------------------------------------------------*/
std::unordered_set<std::pair<unsigned long, bool>, PairHashByFirst, PairEqualByFirst> monitor::pmparser_get_dangerous_instructions
(
	void* addr, size_t len,
	bool sanity_check,
	ScanType type
)
{
	len = ROUND_UP(len, PAGE_SIZE);

	// bool set to true if it is XRSTOR instruction
	// otherwise false
	std::unordered_set<std::pair<unsigned long, bool>, PairHashByFirst, PairEqualByFirst> addresses_to_vet;
	procmaps_iterator* maps = pmparser_parse(mvee::active_monitor->variants[0].variantpid);
	if (maps == nullptr)
		warnf("[map]: cannot parse the memory map of %d\n", mvee::active_monitor->variants[0].variantpid);

	//iterate over areas
	procmaps_struct* maps_tmp;
	while ((maps_tmp = pmparser_next(maps)) != nullptr) {
		// We cannot access [vvar] and [vsyscall] from ptrace:
		//    https://twitter.com/moyix/status/951577738422472704
		//    http://lkml.iu.edu/hypermail/linux/kernel/1503.1/03733.html
		//    https://gist.github.com/moyix/01aa2682d70f6283ccbb7c9c5d44b65f
		if (std::string(maps_tmp->pathname) != "[vvar]" && std::string(maps_tmp->pathname) != "[vsyscall]"
			// what do we want?
			&& (type == EVERYTHING || (type == ONLY_EXEC && maps_tmp->is_x) || (type == ONLY_NON_EXEC && !maps_tmp->is_x))
			// is the region included in this address range?
			&& is_region_included(maps_tmp->addr_start, maps_tmp->length, addr, len))
		{
			debugf("Backed by:\t%s\n", strlen(maps_tmp->pathname) == 0 ? "[anonym*]" : maps_tmp->pathname);
			debugf("Range:\t\t%p-%p\n", maps_tmp->addr_start, maps_tmp->addr_end);
			debugf("Length:\t\t%ld\n", maps_tmp->length);
			debugf("Offset:\t\t%ld\n", maps_tmp->offset);
			debugf("Permissions:\t%s\n", maps_tmp->perm);

			// Our implementation for the moment does not support this
			if (sanity_check && !maps_tmp->is_p) {
				// we do not need to see anything else ... just abort here
				warnf("Trying to make executable a memory region that is shared!!!\n");
				warnf("Our current implementations does not permit that at the moment!!!\n");
				warnf("You Shall Not byPass my PKU-based Sandbox: Not supported use case.\n");
				mvee::active_monitor->shutdown(false);
				break;
			}

			struct stat sb{};
			unsigned long correct_len;

			// Search for the word "beyond" in the following links to understand what is happening here:
			//   https://docs.oracle.com/cd/E88353_01/html/E37841/mmap-2.html
			//   https://www.ibm.com/support/knowledgecenter/ssw_ibm_i_74/apis/mmap.htm
			//   https://man7.org/linux/man-pages/man2/mmap.2.html
			//
			// Any reference to addresses beyond the end of the object, however, will result in the delivery of a SIGBUS or SIGSEGV signal
			// !!! This is important !!!
			if (stat(maps_tmp->pathname, &sb) == 0 && sb.st_size > 0) {
				if (sb.st_size > maps_tmp->offset)
					correct_len = MIN(sb.st_size - (unsigned long)maps_tmp->offset, maps_tmp->length);
				else // yeap we even find cases like that
					continue;
			}
			else {
				correct_len = maps_tmp->length;
			}

			char* buf = new(std::nothrow) char[correct_len];
			// if the region is readable we can use process_vm_readv
			if (maps_tmp->is_r || maps_tmp->is_x) {
				if (!interaction::read_memory(mvee::active_monitor->variants[0].variantpid, maps_tmp->addr_start, correct_len, buf))
					throw RwMemFailure(0, "Process_vm_readv failed to read contents of area that is mapped in the variant\n");
			}
			// otherwise use ptrace
			else {
				if (!interaction::read_memory_ptrace(mvee::active_monitor->variants[0].variantpid, maps_tmp->addr_start, correct_len, buf))
					throw RwMemFailure(0, "Ptrace failed to read contents of area that is mapped in the variant\n");
			}

			auto offsets = erim_memScanRegion(ERIM_UNTRUSTED_PKRU, buf, correct_len, maps_tmp->pathname);
			for (const auto& offset: offsets) {
				unsigned long address_of_dangerous_instruction = (unsigned long)maps_tmp->addr_start + offset.first;
				// permissions may change in a small part of a region, not affecting this instruction
				if ((unsigned long)addr <= address_of_dangerous_instruction && address_of_dangerous_instruction < (unsigned long)addr + len)
					addresses_to_vet.insert(std::make_pair(address_of_dangerous_instruction, offset.second));
			}

			SAFEDELETEARRAY(buf);
		}
	}

	// mandatory: should free the list
	pmparser_free(maps);

	// mandatory: should free the iterator
	SAFEDELETE(maps);

	return addresses_to_vet;
}

bool monitor::pmparser_is_xom_switch_policy_violated(void* addr, size_t len, unsigned long perm)
{
	len = ROUND_UP(len, PAGE_SIZE);

	// bool set to true if it is XRSTOR instruction
	// otherwise false
	std::unordered_set<std::pair<unsigned long, bool>, PairHashByFirst, PairEqualByFirst> addresses_to_vet;
	procmaps_iterator* maps = pmparser_parse(mvee::active_monitor->variants[0].variantpid);
	if (maps == nullptr)
		warnf("[map]: cannot parse the memory map of %d\n", mvee::active_monitor->variants[0].variantpid);

	//iterate over areas
	procmaps_struct* maps_tmp;
	while ((maps_tmp = pmparser_next(maps)) != nullptr) {
		// We cannot access [vvar] and [vsyscall] from ptrace:
		//    https://twitter.com/moyix/status/951577738422472704
		//    http://lkml.iu.edu/hypermail/linux/kernel/1503.1/03733.html
		//    https://gist.github.com/moyix/01aa2682d70f6283ccbb7c9c5d44b65f
		if (std::string(maps_tmp->pathname) != "[vvar]" && std::string(maps_tmp->pathname) != "[vsyscall]"
			// is it execute-only memory?
			&& maps_tmp->is_x && !maps_tmp->is_r && !maps_tmp->is_w
			// do we want to make it readable?
			&& (perm & PROT_READ)
			// is the region included in this address range?
			&& is_region_included(maps_tmp->addr_start, maps_tmp->length, addr, len))
		{
			debugf("Backed by:\t%s\n", strlen(maps_tmp->pathname) == 0 ? "[anonym*]" : maps_tmp->pathname);
			debugf("Range:\t\t%p-%p\n", maps_tmp->addr_start, maps_tmp->addr_end);
			debugf("Length:\t\t%ld\n", maps_tmp->length);
			debugf("Offset:\t\t%ld\n", maps_tmp->offset);
			debugf("Permissions:\t%s\n", maps_tmp->perm);

			return true;
		}
	}

	// mandatory: should free the list
	pmparser_free(maps);

	// mandatory: should free the iterator
	SAFEDELETE(maps);

	return false;
}


/*-----------------------------------------------------------------------------
    get_deleted_dangerous_instructions
-----------------------------------------------------------------------------*/
std::unordered_set<std::pair<unsigned long, bool>, PairHashByFirst, PairEqualByFirst> monitor::get_deleted_dangerous_instructions(void* addr, size_t len)
{
	len = ROUND_UP(len, PAGE_SIZE);

	// bool set to true if it is XRSTOR instruction
	// otherwise false
	std::unordered_set<std::pair<unsigned long, bool>, PairHashByFirst, PairEqualByFirst> deleted_dangerous_instructions;
	for (const auto& dangerous_instruction: mvee::active_monitor->set_mmap_table->active_dangerous_instructions) {
		// find dangerous instructions that are affected (even the ones that cross regions)
		if ((unsigned long)addr - 2 <= dangerous_instruction.first && dangerous_instruction.first < (unsigned long)addr + len)
			deleted_dangerous_instructions.insert(std::make_pair(dangerous_instruction.first, dangerous_instruction.second));
	}

	return deleted_dangerous_instructions;
}

/*-----------------------------------------------------------------------------
    postcall_set_page_prot_non_exec
-----------------------------------------------------------------------------*/
int monitor::postcall_set_page_prot_non_exec(unsigned long addr, bool prot_non_exec)
{
	auto region = pmparser_get_region_info(addr);
	if (!region) {
		warnf("We try to change permissions of a region that doesn't exist\n");
		return -1;
	}

	variantstate* variant = &variants[0];

	addr &= PAGE_MASK;
	// Sanity check on range
	if ((addr + PAGE_SIZE) > (region->region_base_address + region->region_size))
		return -1;
	// We don't need toggling of mappings that already are non-executable.
	// This is just here to prevent constant calling of mprotect when it's not necessary.
	if (prot_non_exec && !(region->region_prot_flags & PROT_EXEC))
		return 0;
	// We don't need to do anything. This is just here to prevent constant calling of mprotect when it's not
	// necessary.
	if (!(prot_non_exec ^ (set_mmap_table->prot_non_exec_map.find(addr) != set_mmap_table->prot_non_exec_map.end())))
		return 0;

	struct user_regs_struct orig_regs{};

	// Store the current register state in the variantstate.
	if (!interaction::read_all_regs(variant->variantpid, &orig_regs))
		throw RwRegsFailure(0, " > something went wrong saving register context\n");

	if (!variant->syscall_jump)
		throw CerberusNotInitializedFailure(0, " > syscall jump is not initialized\n");

#ifdef ENABLE_XOM_SWITCH_POLICY
	// We do not make the page readable to protect XOM memory
	unsigned long protection = prot_non_exec ? ((region->region_prot_flags & ~PROT_EXEC)) : set_mmap_table->prot_non_exec_map[addr];
#else
	// The page remains readable since it may contain read-only data ... and we also want to be able to read it using process_vm_read.
	unsigned long protection = prot_non_exec ? ((region->region_prot_flags & ~PROT_EXEC) | PROT_READ) : set_mmap_table->prot_non_exec_map[addr];
#endif
	interaction::mvee_wait_status status{};

	// Setting up new register context to do mprotect system call.
	struct user_regs_struct register_context = orig_regs;
	register_context.rip = (unsigned long)variant->syscall_jump;
	register_context.rax = __NR_mprotect;
	register_context.rdi = addr;
	register_context.rsi = PAGE_SIZE;
	register_context.rdx = protection;

	// Write the new register context to the tracee.
	if (!interaction::write_all_regs(variant->variantpid, &register_context))
		throw RwRegsFailure(0, " > something went wrong writing new register context\n");

	// Reached the entrance of mprotect syscall.
	call_resume();
	interaction::wait(variant->variantpid, status);
	if (status.reason != STOP_SYSCALL)
		throw PtraceOpFailure(0," > something went wrong at mprotect entrance\n");

	// Now we actually make the tracee do the call.
	call_resume();
	interaction::wait(variant->variantpid, status);
	if (status.reason != STOP_SYSCALL)
		throw PtraceOpFailure(0, " > something went wrong while executing mprotect\n");

	// Sanity check on the result.
	if (!interaction::read_all_regs(variant->variantpid, &register_context))
		throw RwRegsFailure(0, " > something went wrong checking register context\n");

	if (register_context.rax != 0)
		throw PtraceOpFailure(0," > something went wrong with the mprotect call\n");

	// Update our bookkeeping.
	if (prot_non_exec) {
		debugf("Make region starting at %p with size %zu non-executable (but readable) for PKU sandboxing purposes.\n", (void*)addr, PAGE_SIZE);
		set_mmap_table->prot_non_exec_map[addr] = region->region_prot_flags;
	}
	else {
		debugf("Make region starting at %p with size %zu executable for PKU sandboxing purposes.\n", (void*)addr, PAGE_SIZE);
		set_mmap_table->prot_non_exec_map.erase(addr);
	}

	// Reset the original register context.
	if (!interaction::write_all_regs(variant->variantpid, &orig_regs))
		throw RwRegsFailure(0, " > something went wrong writing old register context\n");

	SAFEDELETE(region);

	// Return OK.
	return 0;
}

/*-----------------------------------------------------------------------------
    postcall_init_cerberus_kernel_pku_sandbox
-----------------------------------------------------------------------------*/
void monitor::postcall_init_cerberus_kernel_pku_sandbox()
{
	struct user_regs_struct orig_regs{};
	variantstate* variant = &variants[0];

	// Store the current register state in the variantstate.
	if (!interaction::read_all_regs(variant->variantpid, &orig_regs))
		throw RwRegsFailure(0, " > something went wrong saving register context\n");

	if (!variant->syscall_jump)
		throw CerberusNotInitializedFailure(0, " > syscall jump is not initialized (this should be a bug)\n");

	std::string str = "/proc/" + std::to_string(variant->varianttgid) + "/mem";
	struct stat stats{};
	stat(str.c_str(), &stats);

	int status;
	long result;

	// Setting up new register context to do prctl system call.
	struct user_regs_struct register_context = orig_regs;
	register_context.rip = (unsigned long)variant->syscall_jump;
	register_context.rax = __NR_prctl;
	register_context.rdi = PR_REGISTER_CERBERUS;
	register_context.rsi = stats.st_ino;
	register_context.rdx = 0;
	register_context.r10 = 0;

	// Write the new register context to the tracee.
	if (!interaction::write_all_regs(variant->variantpid, &register_context))
		throw RwRegsFailure(0, " > something went wrong writing new register context\n");

	// Got to prctl syscall entrance.
	if (ptrace(PTRACE_SYSCALL, variant->variantpid, 0, 0))
		throw PtraceOpFailure(0, " > something went wrong going to prctl entrance\n");

	waitpid(variant->variantpid, &status, 0);

	// Now we actually make the tracee do the call.
	result = ptrace(PTRACE_SYSCALL, variant->variantpid, 0, 0);
	if (result != 0)
		throw PtraceOpFailure(0, " > something went wrong while executing prctl\n");

	waitpid(variant->variantpid, &status, 0);

	// Sanity check on the result.
	if (!interaction::read_all_regs(variant->variantpid, &register_context))
		throw RwRegsFailure(0, " > something went wrong checking register context\n");

	if (register_context.rax != 0)
		throw PtraceOpFailure(0, " > something went wrong with the prctl call\n");

	// Reset the original register context.
	if (!interaction::write_all_regs(variant->variantpid, &orig_regs))
		throw RwRegsFailure(0, " > something went wrong writing old register context\n");
}

/*-----------------------------------------------------------------------------
    precall_open_special_fd
-----------------------------------------------------------------------------*/
int monitor::precall_open_special_fd(const std::string& special_path)
{
	int fd = -1;

	if (!variants[0].special_page || !variants[0].syscall_jump)
		throw CerberusNotInitializedFailure(0, " > special page or syscall jump is not initialized (this should be a bug)\n");

	variantstate* variant = &variants[0];
	struct user_regs_struct orig_regs{};

	// Store the current register state in the variantstate
	if (!interaction::read_all_regs(variant->variantpid, &orig_regs))
		throw RwRegsFailure(0, " > something went wrong saving register context\n");

	interaction::mvee_wait_status status{};

	char special_char_path[PAGE_SIZE] = {0};
	std::copy(special_path.begin(), special_path.end(), special_char_path);
	interaction::write_memory_multiple_of_long_len_ptrace(variants[0].variantpid, (void*)((unsigned long)variants[0].special_page), PAGE_SIZE, special_char_path);

	// Setting up new register context to do a special open syscall
	struct user_regs_struct register_context = orig_regs;
	register_context.orig_rax = __NR_open;
	register_context.rdi = (unsigned long)variants[0].special_page;
	register_context.rsi = O_RDONLY;

	// Write the new register context to the tracee
	if (!interaction::write_all_regs(variant->variantpid, &register_context))
		throw RwRegsFailure(0, " > something went wrong writing new register context\n");

	// Execute the special open syscall
	call_resume();
	interaction::wait(variant->variantpid, status);
	if (status.reason != STOP_SYSCALL)
		throw PtraceOpFailure(0, " > something went wrong when executing the special open\n");

	// Store the new register state in the variantstate
	if (!interaction::read_all_regs(variant->variantpid, &register_context))
		throw RwRegsFailure(0, " > something went wrong saving new register context\n");

	// Sanity check
	if ((int)register_context.rax == -1)
		throw PtraceOpFailure(0, " > something went wrong when executing the special open\n");

	fd = (int)register_context.rax;

	// Setting up new register context to do the original system call.
	register_context = orig_regs;
	register_context.rax = variants[0].callnum;
	register_context.rip = (unsigned long)variant->syscall_jump;

	// Write the new register context to the tracee
	if (!interaction::write_all_regs(variant->variantpid, &register_context))
		throw RwRegsFailure(0," > something went wrong writing new register context\n");

	// Go back to original system call and bring it to syscall entrance state
	call_resume();
	interaction::wait(variant->variantpid, status);
	if (status.reason != STOP_SYSCALL)
		throw PtraceOpFailure(0, " > something went wrong when trying to go to the original system call's entrance\n");

	// Reset the original register context.
	if (!interaction::write_all_regs(variant->variantpid, &orig_regs))
		throw RwRegsFailure(0, " > something went wrong writing old register context\n");

	return fd;
}

/*-----------------------------------------------------------------------------
    precall_syscall
-----------------------------------------------------------------------------*/
long monitor::precall_syscall(unsigned long syscall_no, unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5, unsigned long arg6)
{
	variantstate* variant = &variants[0];
	struct user_regs_struct orig_regs{};
	long result = 0;

	// Store the current register state in the variantstate
	if (!interaction::read_all_regs(variant->variantpid, &orig_regs))
		throw RwRegsFailure(0, " > something went wrong saving register context\n");

	interaction::mvee_wait_status status{};

	// Setting up new register context to do syscall
	struct user_regs_struct register_context = orig_regs;
	register_context.orig_rax = syscall_no;
	register_context.rdi = arg1;
	register_context.rsi = arg2;
	register_context.rdx = arg3;
	register_context.r10 = arg4;
	register_context.r8  = arg5;
	register_context.r9  = arg6;

	// Write the new register context to the tracee
	if (!interaction::write_all_regs(variant->variantpid, &register_context))
		throw RwRegsFailure(0, " > something went wrong writing new register context\n");

	// Execute the syscall
	call_resume();
	interaction::wait(variant->variantpid, status);
	if (status.reason != STOP_SYSCALL)
		throw PtraceOpFailure(0, " > something went wrong when executing the syscall\n");

	// Store the new register state in the variantstate
	if (!interaction::read_all_regs(variant->variantpid, &register_context))
		throw RwRegsFailure(0, " > something went wrong saving new register context\n");

	// the result of the syscall
	result = register_context.rax;

	// Setting up new register context to do the original system call.
	register_context = orig_regs;
	register_context.rax  = variants[0].callnum;
	register_context.rip -= SYSCALL_INS_LEN;

	// Write the new register context to the tracee
	if (!interaction::write_all_regs(variant->variantpid, &register_context))
		throw RwRegsFailure(0," > something went wrong writing new register context\n");

	// Go back to original system call and bring it to syscall entrance state
	call_resume();
	interaction::wait(variant->variantpid, status);
	if (status.reason != STOP_SYSCALL)
		throw PtraceOpFailure(0, " > something went wrong when trying to go to the original system call's entrance\n");

	// Reset the original register context.
	if (!interaction::write_all_regs(variant->variantpid, &orig_regs))
		throw RwRegsFailure(0, " > something went wrong writing old register context\n");

	return result;
}

/*-----------------------------------------------------------------------------
    cerberus_set_unchecked_syscall
-----------------------------------------------------------------------------*/
void monitor::cerberus_set_unchecked_syscall(unsigned char* mask, unsigned long syscall_no, unsigned char unchecked)
{
	unsigned long no_to_byte, bit_in_byte;

	if (syscall_no > ROUND_UP(__NR_syscalls, 8))
		return;

	no_to_byte  = syscall_no / 8;
	bit_in_byte = syscall_no % 8;

	if (unchecked)
		mask[no_to_byte] |= (1 << (7 - bit_in_byte));
	else
		mask[no_to_byte] &= ~(1 << (7 - bit_in_byte));
}

/*-----------------------------------------------------------------------------
    precall_init_cerberus
-----------------------------------------------------------------------------*/
void monitor::precall_init_cerberus()
{
	// mmap a page for cerberusmask
	long addr = precall_syscall(__NR_mmap, 0, PAGE_SIZE, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if ((void*)addr == MAP_FAILED) {
		warnf("mmap a page for cerberusmask failed\n");
		shutdown(false);
		return;
	}

	CERBERUS_MASK(cerberusmask);
	CERBERUS_MASK_CLEAR(cerberusmask);

	CERBERUS_MASK_SET(cerberusmask, __NR_getegid);
	CERBERUS_MASK_SET(cerberusmask, __NR_geteuid);
	CERBERUS_MASK_SET(cerberusmask, __NR_getgid);
	CERBERUS_MASK_SET(cerberusmask, __NR_getpgrp);
	CERBERUS_MASK_SET(cerberusmask, __NR_getppid);
	CERBERUS_MASK_SET(cerberusmask, __NR_gettid);
	CERBERUS_MASK_SET(cerberusmask, __NR_getuid);
	CERBERUS_MASK_SET(cerberusmask, __NR_getpid);
	CERBERUS_MASK_SET(cerberusmask, __NR_gettimeofday);
	CERBERUS_MASK_SET(cerberusmask, __NR_time);
	CERBERUS_MASK_SET(cerberusmask, __NR_clock_gettime);
	CERBERUS_MASK_SET(cerberusmask, __NR_sched_yield);
	CERBERUS_MASK_SET(cerberusmask, __NR_getcwd);
	CERBERUS_MASK_SET(cerberusmask, __NR_uname);
	CERBERUS_MASK_SET(cerberusmask, __NR_getpriority);
	CERBERUS_MASK_SET(cerberusmask, __NR_nanosleep);
	CERBERUS_MASK_SET(cerberusmask, __NR_getrusage);
	CERBERUS_MASK_SET(cerberusmask, __NR_sysinfo);
	CERBERUS_MASK_SET(cerberusmask, __NR_times);
	CERBERUS_MASK_SET(cerberusmask, __NR_capget);
	CERBERUS_MASK_SET(cerberusmask, __NR_getitimer);
	CERBERUS_MASK_SET(cerberusmask, __NR_set_tid_address);

	CERBERUS_MASK_SET(cerberusmask, __NR_access);
	CERBERUS_MASK_SET(cerberusmask, __NR_faccessat);
	CERBERUS_MASK_SET(cerberusmask, __NR_stat);
	CERBERUS_MASK_SET(cerberusmask, __NR_lstat);
	CERBERUS_MASK_SET(cerberusmask, __NR_fstat);
	CERBERUS_MASK_SET(cerberusmask, __NR_newfstatat);
	CERBERUS_MASK_SET(cerberusmask, __NR_getdents);
	CERBERUS_MASK_SET(cerberusmask, __NR_readlink);
	CERBERUS_MASK_SET(cerberusmask, __NR_readlinkat);
	CERBERUS_MASK_SET(cerberusmask, __NR_getxattr);
	CERBERUS_MASK_SET(cerberusmask, __NR_lgetxattr);
	CERBERUS_MASK_SET(cerberusmask, __NR_fgetxattr);
	CERBERUS_MASK_SET(cerberusmask, __NR_lseek);
	CERBERUS_MASK_SET(cerberusmask, __NR_alarm);
	CERBERUS_MASK_SET(cerberusmask, __NR_setitimer);
	CERBERUS_MASK_SET(cerberusmask, __NR_timerfd_gettime);
	CERBERUS_MASK_SET(cerberusmask, __NR_madvise);
	CERBERUS_MASK_SET(cerberusmask, __NR_fadvise64);

	CERBERUS_MASK_SET(cerberusmask, __NR_read);
	CERBERUS_MASK_SET(cerberusmask, __NR_readv);
	CERBERUS_MASK_SET(cerberusmask, __NR_pread64);
	CERBERUS_MASK_SET(cerberusmask, __NR_preadv);
	CERBERUS_MASK_SET(cerberusmask, __NR_select);
	CERBERUS_MASK_SET(cerberusmask, __NR_poll);
	// CERBERUS_MASK_SET(cerberusmask, __NR_ioctl);
	CERBERUS_MASK_SET(cerberusmask, __NR_futex);

	CERBERUS_MASK_SET(cerberusmask, __NR_timerfd_settime);
	CERBERUS_MASK_SET(cerberusmask, __NR_sync);
	CERBERUS_MASK_SET(cerberusmask, __NR_fsync);
	CERBERUS_MASK_SET(cerberusmask, __NR_fdatasync);
	CERBERUS_MASK_SET(cerberusmask, __NR_syncfs);

	CERBERUS_MASK_SET(cerberusmask, __NR_write);
	CERBERUS_MASK_SET(cerberusmask, __NR_writev);
	CERBERUS_MASK_SET(cerberusmask, __NR_pwrite64);
	CERBERUS_MASK_SET(cerberusmask, __NR_pwritev);

	CERBERUS_MASK_SET(cerberusmask, __NR_epoll_wait);
	CERBERUS_MASK_SET(cerberusmask, __NR_recvfrom);
	CERBERUS_MASK_SET(cerberusmask, __NR_recvmsg);
	CERBERUS_MASK_SET(cerberusmask, __NR_recvmmsg);
	CERBERUS_MASK_SET(cerberusmask, __NR_getsockname);
	CERBERUS_MASK_SET(cerberusmask, __NR_getpeername);
	CERBERUS_MASK_SET(cerberusmask, __NR_getsockopt);

	CERBERUS_MASK_SET(cerberusmask, __NR_sendto);
	CERBERUS_MASK_SET(cerberusmask, __NR_sendmsg);
	CERBERUS_MASK_SET(cerberusmask, __NR_sendmmsg);
	CERBERUS_MASK_SET(cerberusmask, __NR_sendfile);
	CERBERUS_MASK_SET(cerberusmask, __NR_shutdown);
	CERBERUS_MASK_SET(cerberusmask, __NR_setsockopt);
	CERBERUS_MASK_SET(cerberusmask, __NR_epoll_ctl);

	// Memory Management
	// CERBERUS_MASK_SET(cerberusmask, __NR_mmap);
	// CERBERUS_MASK_SET(cerberusmask, __NR_munmap);
	// CERBERUS_MASK_SET(cerberusmask, __NR_mremap);
	// CERBERUS_MASK_SET(cerberusmask, __NR_mprotect);
	CERBERUS_MASK_SET(cerberusmask, __NR_brk);

	// File Management
	CERBERUS_MASK_SET(cerberusmask, __NR_open);
	CERBERUS_MASK_SET(cerberusmask, __NR_openat);
	CERBERUS_MASK_SET(cerberusmask, __NR_creat);
	CERBERUS_MASK_SET(cerberusmask, __NR_close);
	CERBERUS_MASK_SET(cerberusmask, __NR_fcntl);
	CERBERUS_MASK_SET(cerberusmask, __NR_dup);
	CERBERUS_MASK_SET(cerberusmask, __NR_dup2);
	CERBERUS_MASK_SET(cerberusmask, __NR_dup3);
	CERBERUS_MASK_SET(cerberusmask, __NR_pipe);
	CERBERUS_MASK_SET(cerberusmask, __NR_pipe2);
	CERBERUS_MASK_SET(cerberusmask, __NR_inotify_init);
	CERBERUS_MASK_SET(cerberusmask, __NR_inotify_init1);

	// Directory management
	CERBERUS_MASK_SET(cerberusmask, __NR_chdir);
	CERBERUS_MASK_SET(cerberusmask, __NR_fchdir);
	CERBERUS_MASK_SET(cerberusmask, __NR_mkdir);

	// Socket Management
	CERBERUS_MASK_SET(cerberusmask, __NR_socket);
	CERBERUS_MASK_SET(cerberusmask, __NR_socketpair);
	CERBERUS_MASK_SET(cerberusmask, __NR_bind);
	CERBERUS_MASK_SET(cerberusmask, __NR_connect);
	CERBERUS_MASK_SET(cerberusmask, __NR_listen);
	CERBERUS_MASK_SET(cerberusmask, __NR_accept4);
	CERBERUS_MASK_SET(cerberusmask, __NR_accept);
	CERBERUS_MASK_SET(cerberusmask, __NR_epoll_create);
	CERBERUS_MASK_SET(cerberusmask, __NR_epoll_create1);

	interaction::write_memory(variants[0].variantpid, (void*)addr, ROUND_UP(__NR_syscalls, 8) / 8, cerberusmask);

	std::string str = "/proc/" + std::to_string(variants[0].variantpid) + "/mem";
	struct stat stats{};
	stat(str.c_str(), &stats);
	long ret = precall_syscall(__NR_prctl, PR_REGISTER_CERBERUS, stats.st_ino, addr, ROUND_UP(__NR_syscalls, 8) / 8, 0, 0);
	if (ret != 0) {
		warnf("WARNING: Cerberus kernel PKU sandbox has been activated through MVEE_build_config.h,\n");
		warnf("WARNING: but we could not detect an Cerberus kernel PKU sandbox compatible kernel.\n");
		warnf("WARNING:\n");
		warnf("WARNING: Abort Now!\n");
		shutdown(false);
		return;
	}

	if (precall_syscall(__NR_munmap, addr, PAGE_SIZE, 0, 0, 0, 0) != 0) {
		warnf("munmap cerberusmask page failed\n");
		shutdown(false);
		return;
	}
}

/*-----------------------------------------------------------------------------
    precall_set_infinite_loop
-----------------------------------------------------------------------------*/
void monitor::precall_set_infinite_loop()
{
	// mmap a page for infinite loop
	long addr = precall_syscall(__NR_mmap, 0, PAGE_SIZE, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if ((void*)addr == MAP_FAILED) {
		warnf("mmap a page for infinite loop failed\n");
		shutdown(false);
		return;
	}

	// we add at +500 offset to avoid dangerous instructions across region case
	long_and_bytes address_to_bytes{};
	address_to_bytes.value = (long) (addr + 500);
	unsigned char infinite_loop[17];

	// useful links
	// https://stackoverflow.com/questions/38961192/how-to-execute-a-call-instruction-with-a-64-bit-absolute-address
	// https://stackoverflow.com/questions/19415184/load-from-a-64-bit-address-into-other-register-than-rax
	// https://stackoverflow.com/questions/46594389/movabs-opcode-in-the-assembly-code
	// https://stackoverflow.com/questions/10272027/x86-jmp-to-register
	// https://www.ragestorm.net/blogs/?p=101
	// https://www.unknowncheats.me/forum/assembly/209469-absolute-jmp-call-snippets.html
	// https://stackoverflow.com/questions/33469531/x64-how-to-do-a-relative-jmp-rax

	//0:  90                      nop
	//1:  90                      nop
	//2:  90                      nop
	//3:  90                      nop
	//4:  90                      nop
	infinite_loop[0]  = 0x90;
	infinite_loop[1]  = 0x90;
	infinite_loop[2]  = 0x90;
	infinite_loop[3]  = 0x90;
	infinite_loop[4]  = 0x90;

	//5:  48 b8 00 d0 9c a9 00    movabs rax, 64-bit address (e.g., 0x7f00a99cd000)
	//c:  7f 00 00
	infinite_loop[5]  = 0x48;
	infinite_loop[6]  = 0xb8;
	infinite_loop[7]  = address_to_bytes.bytes[0];
	infinite_loop[8]  = address_to_bytes.bytes[1];
	infinite_loop[9]  = address_to_bytes.bytes[2];
	infinite_loop[10]  = address_to_bytes.bytes[3];
	infinite_loop[11]  = address_to_bytes.bytes[4];
	infinite_loop[12]  = address_to_bytes.bytes[5];
	infinite_loop[13]  = address_to_bytes.bytes[6];
	infinite_loop[14]  = address_to_bytes.bytes[7];

	//f:  ff e0                   jmp   rax
	infinite_loop[15]  = 0xff;
	infinite_loop[16]  = 0xe0;

	interaction::write_memory(variants[0].variantpid, (void*)(addr + 500), 17, infinite_loop);
	precall_syscall(__NR_mprotect, addr, PAGE_SIZE, PROT_READ | PROT_EXEC, 0, 0, 0);

	variants[0].infinite_loop_ptr = addr + 500;
}

/*-----------------------------------------------------------------------------
    precall_set_jumps_and_special_page
-----------------------------------------------------------------------------*/
void monitor::precall_set_jumps_and_special_page()
{
	// MAP_SHARED | MAP_ANONYMOUS for some reason is shown that is backed from /dev/zero in /proc/<PID>/maps
	// Consequently, we changed that to MAP_PRIVATE | MAP_ANONYMOUS
	long addr = precall_syscall(__NR_mmap, 0, PAGE_SIZE, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if ((void*)addr == MAP_FAILED) {
		warnf("mmap a page for jumps failed\n");
		shutdown(false);
		return;
	}

	unsigned char jumps[5];
	// syscall -> { 0x0F, 0x05 }
	// we add at +500 offset to avoid dangerous instructions across region case
	jumps[0] = 0x0f;
	jumps[1] = 0x05;

	// rdpkru -> { 0x0F, 0x01, 0xEE }
	jumps[2] = 0x0f;
	jumps[3] = 0x01;
	jumps[4] = 0xee;

	interaction::write_memory(variants[0].variantpid, (void*)(addr + 500), 5, jumps);
	precall_syscall(__NR_mprotect, addr, PAGE_SIZE, PROT_READ | PROT_EXEC, 0, 0, 0);

	variants[0].syscall_jump = (void*)(addr + 500);
	variants[0].get_pku_domain_jump = (void*)(addr + 502);

	addr = precall_syscall(__NR_mmap, 0, PAGE_SIZE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if ((void*)addr == MAP_FAILED) {
		warnf("mmap a special page failed\n");
		shutdown(false);
		return;
	}

	variants[0].special_page = (void*)addr;
}

/*-----------------------------------------------------------------------------
    postcall_close_special_fd
-----------------------------------------------------------------------------*/
void monitor::postcall_close_special_fd(int special_fd)
{
	struct user_regs_struct orig_regs{};
	variantstate* variant = &variants[0];

	// Store the current register state in the variantstate.
	if (!interaction::read_all_regs(variant->variantpid, &orig_regs))
		throw RwRegsFailure(0, " > something went wrong saving register context\n");

	if (!variant->syscall_jump)
		throw CerberusNotInitializedFailure(0, " > syscall jump is not initialized (this should be a bug)\n");

	int status;
	long result;

	// Setting up new register context to do close special fd system call.
	struct user_regs_struct register_context = orig_regs;
	register_context.rip = (unsigned long)variant->syscall_jump;
	register_context.rax = __NR_close;
	register_context.rdi = special_fd;

	// Write the new register context to the tracee.
	if (!interaction::write_all_regs(variant->variantpid, &register_context))
		throw RwRegsFailure(0, " > something went wrong writing new register context\n");

	// Got to close special fd syscall entrance.
	if (ptrace(PTRACE_SYSCALL, variant->variantpid, 0, 0))
		throw PtraceOpFailure(0, " > something went wrong going to close special fd entrance\n");

	waitpid(variant->variantpid, &status, 0);

	// Now we actually make the tracee do the call.
	result = ptrace(PTRACE_SYSCALL, variant->variantpid, 0, 0);
	if (result != 0)
		throw PtraceOpFailure(0, " > something went wrong while executing close special fd\n");

	waitpid(variant->variantpid, &status, 0);

	if (!interaction::read_all_regs(variant->variantpid, &register_context))
		throw RwRegsFailure(0, " > something went wrong checking register context\n");

	// Sanity check on the result.
	if (register_context.rax != 0)
		throw PtraceOpFailure(0, " > something went wrong with the close special fd call\n");

	// Reset the original register context.
	if (!interaction::write_all_regs(variant->variantpid, &orig_regs))
		throw RwRegsFailure(0, " > something went wrong writing old register context\n");
}

/*-----------------------------------------------------------------------------
    precall_get_pku_domain

    !!! This method only works at precall handlers !!!
    // TODO FIXME Not tested anymore
    // TODO FIXME if we receive a signal we do not recover
-----------------------------------------------------------------------------*/
int monitor::precall_get_pku_domain()
{
	int ret = DEFAULT_PKRU_VALUE;

	// We assume that we are in the default domain until these values are initialized by the MVEE_LD_Loader
	if (variants[0].syscall_jump && variants[0].get_pku_domain_jump) {
		variantstate *variant = &variants[0];
		struct user_regs_struct orig_regs{};

		// Store the current register state in the variantstate
		if (!interaction::read_all_regs(variant->variantpid, &orig_regs))
			throw RwRegsFailure(0, " > something went wrong saving register context\n");

		interaction::mvee_wait_status status{};
		long result;

		// Setting up new register context to do a fake syscall (getpid)
		struct user_regs_struct register_context = orig_regs;
		register_context.orig_rax = __NR_getpid;

		// Write the new register context to the tracee
		if (!interaction::write_all_regs(variant->variantpid, &register_context))
			throw RwRegsFailure(0, " > something went wrong writing new register context\n");

		// Execute the fake syscall (getpid) to bring the tracee in a postcall state ... this is a hack!!!
		call_resume();
		interaction::wait(variant->variantpid, status);
		if (status.reason != STOP_SYSCALL)
			warnf(" > something went wrong when executing the fake syscall (getpid) - %d\n", errno);

		// Store the new register state in the variantstate
		if (!interaction::read_all_regs(variant->variantpid, &register_context))
			throw RwRegsFailure(0, " > something went wrong saving new register context\n");

		// Sanity check
		if ((int)register_context.rax != variant->variantpid)
			warnf(" > something went wrong while executing the fake syscall (getpid) - %d\n", errno);

		// Setting up new register context to get the PKU domain
		register_context = orig_regs;
		register_context.rip = (unsigned long)variant->get_pku_domain_jump;
		register_context.rcx = 0; // this is required from rdpkru instruction

		// Write the new register context to the tracee
		if (!interaction::write_all_regs(variant->variantpid, &register_context))
			throw RwRegsFailure(0, " > something went wrong writing new register context\n");

		// Get PKU domain
		result = ptrace(PTRACE_SINGLESTEP, variant->variantpid, 0, 0);
		if (result != 0)
			warnf(" > something went wrong while getting PKU domain - %d\n", errno);
		interaction::wait(variant->variantpid, status);
		if (status.reason != STOP_NOTSTOPPED)
			warnf(" > something went wrong when reading the PKU domain - %d\n", errno);

		// Store the new register state in the variantstate
		if (!interaction::read_all_regs(variant->variantpid, &register_context))
			throw RwRegsFailure(0, " > something went wrong saving new register context\n");

		ret = (int)register_context.rax;
		// warnf("rax is %llx\n", register_context.rax);

		// Setting up new register context to do the original system call.
		register_context = orig_regs;
		register_context.rax = variants[0].callnum;
		register_context.rip = (unsigned long)variant->syscall_jump;

		// Write the new register context to the tracee
		if (!interaction::write_all_regs(variant->variantpid, &register_context))
			throw RwRegsFailure(0," > something went wrong writing new register context\n");

		// Go back to original system call and bring it to syscall entrance state
		call_resume();
		interaction::wait(variant->variantpid, status);
		if (status.reason != STOP_SYSCALL)
			warnf(" > something went wrong when trying to go to the original system call's entrance - %d\n", errno);

		// Reset the original register context.
		if (!interaction::write_all_regs(variant->variantpid, &orig_regs))
			throw RwRegsFailure(0, " > something went wrong writing old register context\n");
	}

	return ret;
}

/*-----------------------------------------------------------------------------
    clear_log_folder - called during startup
-----------------------------------------------------------------------------*/
void mvee::special_init()
{
	char cmd[1024];

	// create the folder if needed
	sprintf(cmd, "mkdir -p %s", SPECIALDIR);
	if (system(cmd) < 0)
		printf("Couldn't create special folder: %s\n", SPECIALDIR);

	// delete any existing "special" files
	sprintf(cmd, "rm -f %s* 2>&1", SPECIALDIR);
	if (system(cmd) < 0)
		printf("Couldn't clear special folder: %s\n", SPECIALDIR);
}

/*-----------------------------------------------------------------------------
    cerberus_create_special_file
-----------------------------------------------------------------------------*/
std::string mvee::cerberus_create_special_file(const std::string& full_path)
{
	struct stat sb{};

	// if no backing file or special file ... may need to add more files like that here
	// these are not dangerous cases:
	//    MAP_ANONYMOUS | MAP_PRIVATE regions are initialized to 0
	//    special files like /dev/zero will never contain dangerous instructions
	if (full_path.empty() || full_path == std::string("/dev/zero") || full_path == std::string("/dev/null") || stat(full_path.c_str(), &sb) < 0) {
		debugf("%s is a file that we cannot create its special equivalent\n", full_path.c_str());
		return "";
	}

	char* writable_path = new char[full_path.size() + 1];
	std::copy(full_path.begin(), full_path.end(), writable_path);
	writable_path[full_path.size()] = '\0';

	struct stat special_sb{};
	std::string special_path = mvee::os_get_orig_working_dir() + "/" + SPECIALDIR + std::string(basename(writable_path));

	debugf("Special path is %s\n", special_path.c_str());
	if (stat(special_path.c_str(), &special_sb) < 0) {
		debugf("Special file %s does not exist. We need to copy it from %s. Progress ...\n", special_path.c_str(), full_path.c_str());

		std::ifstream source(full_path, std::ios::binary);
		std::ofstream dest(special_path, std::ios::binary);
		dest << source.rdbuf();

		if (source.good() && dest.good()) {
			debugf("Success creating %s!!!\n", special_path.c_str());
		}
		else {
			warnf("Failure creating %s!!!\n", special_path.c_str());
			mvee::active_monitor->shutdown(false);
		}

		source.close();
		dest.close();
	}
	else {
		debugf("Special file %s exists. We do not need to do anything.\n", special_path.c_str());
	}

	mvee::special_files.insert(special_sb.st_ino);
	SAFEDELETEARRAY(writable_path);

	return special_path;
}
