/*
 * Cerberus PKU-based Sandbox
 *
 * Check Cerberus/cerberus_ReMon/README.md for licensing terms.
 */

#ifndef MVEE_MACROS_H_
#define MVEE_MACROS_H_

/*-----------------------------------------------------------------------------
  Generic Macros
-----------------------------------------------------------------------------*/
#define ROUND_DOWN(x, multiple) ( (((long)(x)))  & (~(multiple-1)) )
#define ROUND_UP(x, multiple)   ( (((long)(x)) + multiple-1)  & (~(multiple-1)) )

#define SAFEDELETEARRAY(a) \
	if (a != NULL)         \
	{                      \
		delete[] a;        \
		a = NULL;          \
	}

#define SAFEDELETE(a) \
	if (a != NULL)    \
	{                 \
		delete a;     \
		a = NULL;     \
	}

#define MIN(a, b)               ((a>b) ? b : a)
#define MAX(a, b)               ((a>b) ? a : b)

#define OLDCALLIFNOT(newcallnum) \
	((variants[0].callnum == newcallnum) ? false : true)

//
// Returns true if a and b are both NULL, false otherwise
//
#define COMPARE_NULL(a, b)      ( ((void*)a == NULL) == ((void*)b == NULL) )

#define ARRAYLENGTH(a)          ((int)(sizeof(a)/sizeof(a[0])))

#define CHECK_BIT(var, pos) ((var) & (1UL<<(pos)))

//
// Returns the page that the virtual address belongs to
// !!! PAGE_SIZE is defined in MVEE_pkeys.h !!!
//
#define PAGE_OF_ADDRESS(addr) ((void*)((unsigned long long)(addr) & ~(PAGE_SIZE-1)))

#define likely(x)   __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)

#define CERBERUS_MASK(cerberusmask) 					unsigned char cerberusmask[ROUND_UP(__NR_syscalls, 8) / 8]
#define CERBERUS_MASK_CLEAR(cerberusmask) 				memset(cerberusmask, 0, ROUND_UP(__NR_syscalls, 8) / 8)
#define CERBERUS_MASK_SET(cerberusmask, syscall) 		cerberus_set_unchecked_syscall(cerberusmask, syscall, 1)

#ifndef __NR_syscalls
#define __NR_syscalls 335
#endif

#endif /* MVEE_MACROS_H_ */
