#ifndef __TYPES_H__
#define __TYPES_H__

#include <ctype.h>		//for isprint()
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>		//for S_ISSOCK()
#include <sys/socket.h>		//for enum __socket_type and socketFamily
#include <linux/net.h>		//for enum socket_state
#include <unistd.h>
#include <sys/ptrace.h>

//for mmap
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>

//for ptrace directory listing
#include <dirent.h>
#include <signal.h>
#include <errno.h>

#include <sys/wait.h>

// Host architecture
//#define SOURCE_X86_64

/*
 * Target architecture
 * can be read from config file: CONFIG_X86_64=y or
 * CONFIG_X86_32=y  or CONFIG_64BIT=y or read from new_utsname field machine
 */
#define X86_64	1

#define TRUE 1
#define FALSE 0
#define EXTRACT_NW_INFO FALSE
#define EXTRACT_CPUUSAGE_INFO TRUE

enum OFFSETS {
	START_OFFSETS,

    CONFIG_HZ,
	
    NS_UTSNAME_OFFSET,
	NEW_UTSNAME_LEN,

	CPUINFO_FAMILY_OFFSET,
	CPUINFO_VENDOR_OFFSET,
	CPUINFO_MODEL_OFFSET,
	CPUINFO_VENDOR_ID_OFFSET,
	CPUINFO_MODEL_ID_OFFSET,
	CPUINFO_CACHE_SIZE_OFFSET,
	CPUINFO_MAX_CORES_OFFSET,

	VM_STAT_FREE_PAGES_OFFSET,

	STATE_OFFSET,
	LIST_HEAD_OFFSET,
	COMM_OFFSET,
	PID_OFFSET,
	REAL_PARENT_OFFSET,
	TASK_COMM_LEN,

	PIDLINK_OFFSET,
	PIDLINK_PID_OFFSET,

	EXITSTATE_OFFSET,
	TASK_FLAGS_OFFSET,

	TASK_UTIME_OFFSET,
	TASK_STIME_OFFSET,
	TASK_START_TIME_OFFSET,
	TASK_REAL_START_TIME_OFFSET,
	NR_CPUUSAGE_STATS,

	TASK_SCHEDENTITY_OFFSET,
	SCHEDENTITY_SUMEXECRUNTIME_OFFSET,
	SCHEDENTITY_SCHEDSTATS_OFFSET,
	SCHEDSTATS_WAITSUM_OFFSET,
	SCHEDSTATS_IOWAITSUM_OFFSET,

	TASK_MM_OFFSET,
	MM_VMA_OFFSET,
	MM_ARG_START_OFFSET,
	MM_ARG_END_OFFSET,
	MM_PGD_OFFSET,
	MM_LIST_HEAD_OFFSET,
	MM_TOTAL_VM_OFFSET,
	MM_RSS_OFFSET,

	NR_MM_COUNTERS,
	VMA_START_OFFSET,
	VMA_END_OFFSET,
	VMA_NEXT_OFFSET,
	VMA_PREV_OFFSET,
	VMA_FILE_OFFSET,
	VMA_PGOFF_OFFSET,

	FILES_OFFSET,
	FDT_OFFSET,
	MAX_FDS_OFFSET,
	OPEN_FDS_OFFSET,

	FD_ARR_OFFSET,
	NEXT_FDT_OFFSET,
	FD_PATH_OFFSET,
	PATH_VFSMOUNT_OFFSET,
	VFSMOUNT_MOUNTPOINT_DENTRY_OFFSET,
	PATH_DENTRY_OFFSET,
	DENTRY_PARENT_OFFSET,
	DENTRY_INODE_OFFSET,
	DENTRY_LEN_OFFSET,
	DENTRY_NAME_OFFSET,
	INODE_MODE_OFFSET,

	INODE_SOCKET_OFFSET,
	SOCKET_STATE_OFFSET,
	SOCKET_TYPE_OFFSET,
	SOCKET_SOCK_OFFSET,
	SOCK_DADDR_OFFSET,
	SOCK_SADDR_OFFSET,
	SOCK_FAMILY_OFFSET,
	SOCK_DPORT_OFFSET,
	SOCK_SPORT_OFFSET,

	MODULE_STATE_OFFSET,
	MODULE_LIST_HEAD_OFFSET,
	MODULE_NAME_OFFSET,
	MODULE_NAME_LEN,

	NET_DEV_BASE_LIST_HEAD_OFFSET,
	NET_DEVICE_SIZE,
	NET_DEVICE_DEV_LIST_OFFSET,
	NET_DEVICE_NAME_OFFSET,
	NET_DEVICE_IFNAMSIZ,
	NET_DEVICE_ADDR_LEN_OFFSET,
	NET_DEVICE_DEV_ADDR_OFFSET,

	NET_DEVICE_IN_DEVICE_OFFSET,
	IN_DEVICE_IFADDR_LIST_OFFSET,
	IFADDR_NEXT_OFFSET,
	IFADDR_IPADDR_OFFSET,
	IFADDR_MASK_OFFSET,
	IFADDR_BROADCAST_OFFSET,

	NET_DEVICE_STATS_OFFSET,
	STATS_TX_BYTES_OFFSET,
	STATS_TX_PACKETS_OFFSET,
	STATS_RX_BYTES_OFFSET,
	STATS_RX_PACKETS_OFFSET,

	NET_DEVICE_VIRTNET_INFO_OFFSET,
	VIRTNET_INFO_VIRTNET_STATS_OFFSET,
	VIRTNET_STATS_TX_BYTES_OFFSET,
	VIRTNET_STATS_TX_PACKETS_OFFSET,
	VIRTNET_STATS_RX_BYTES_OFFSET,
	VIRTNET_STATS_RX_PACKETS_OFFSET,

	END_OFFSETS
};

enum SYSMAP_ADDR {
	START_SYSMAP,

	INIT_UTS_NS,
	CPU_KHZ,
	BOOT_CPU_DATA,
	NUM_PROCESSORS,
	TOTALRAM_PAGES,
	VM_STAT,
	INIT_TASK,
	MODULES,
	SWAPPER_PG_DIR,
	INIT_LEVEL4_PGT,
	INIT_NET,
	__PER_CPU_OFFSET,
	KERNEL_CPUSTAT,
	KSTAT,
	JIFFIES_64,

	END_SYSMAP
};

//for int buf; READ_ELEM(&buf);
//using retVal = 0 so that it acts as NULL as well
#define READ_ELEM(ctx, buf, offset) do {				   \
	if (read_elem(ctx, buf, phy_mem_offset(offset), sizeof(*buf)) == -1) {\
		return 0;						   \
	}								   \
} while(0)


//for char buf[20]; READ_ELEM(ctxbuf);
#define READ_ELEM1(ctx, buf, offset) do {				   \
	if (read_elem(ctx, buf, phy_mem_offset(offset), sizeof(buf)) == -1) { \
		return 0;						   \
	}								   \
} while(0)


#define TEST_RET_VAL(x) do {						   \
	if (x == -1) {							   \
		return 0;						   \
	}								   \
} while(0)

#ifdef VERBOSE
#define LOG(...)		printf(__VA_ARGS__)
#define ERROR(...)		fprintf(stderr, __VA_ARGS__)
#else
#define LOG(...)
#define ERROR(...)
#endif


#ifndef USE_QEMU_VMEM
#define USE_QEMU_VMEM TRUE
#endif

#ifndef USE_PTRACE
#define USE_PTRACE FALSE
#endif

//#if USE_PTRACE == TRUE
//      #include <sys/ptrace.h>
//#endif

#if EXTRACT_NW_INFO == TRUE
FILE *nw_info_fd;
int log_nw_info = FALSE;
#endif




/*
 * x86_64; for kernel space; maps to physical addr 0 on 64 but arch; #define
 * KERNEL_IMAGE_START _AC(0xffffffff80000000, UL) in
 * /arch/x86/include/asm/page_64_types.h
 */
#define KERN1			0xffffffff80000000
// CONFIG_HZ=1000 in linux build config file
//#define CONFIG_HZ		1000

typedef int s32;
typedef unsigned int u32;

typedef long long s64;
typedef unsigned long long u64;

// if 64 bit environment, could also use __LP64__
#ifdef X86_64
#define FMT_ULONG		"llu"
#define FMT_LONG_X		"llx"
#else
#define FMT_ULONG		"u"
#define FMT_LONG_X		"x"
#endif

// Target virtual machine architecture.
#ifdef X86
// CONFIG_PAGE_OFFSET=0xc0000000 in linux build config file
#define KERN 			0xc0000000
#define KERNEL_PGD		ctx->sym_addr[SWAPPER_PG_DIR]

#define PGDIR_SHIFT		22
#define PTRS_PER_PGD		1024

#define PUD_SHIFT		PGDIR_SHIFT
#define PTRS_PER_PUD		1

#define PMD_SHIFT		PUD_SHIFT
#define PTRS_PER_PMD		1

#define PTRS_PER_PTE		1024

#define PTR_SIZE		sizeof(u32)	//32 bit 4 bytes

#define __PHYSICAL_MASK_SHIFT	32

typedef u32 pgd_t;
typedef u32 pud_t;
typedef u32 pmd_t;
typedef u32 pt_t;

typedef u32 addr_t;
typedef u32 ul_t;
typedef s32 l_t;

#endif

#ifdef X86_PAE
#define KERN 			0xc0000000
#define KERNEL_PGD		ctx->sym_addr[SWAPPER_PG_DIR]

#define PGDIR_SHIFT		30
#define PTRS_PER_PGD		4

#define PUD_SHIFT		PGDIR_SHIFT
#define PTRS_PER_PUD		1

#define PMD_SHIFT		21
#define PTRS_PER_PMD		512

#define PTRS_PER_PTE		512

#define PTR_SIZE		sizeof(u64)

#define __PHYSICAL_MASK_SHIFT	44

typedef u32 pgd_t;		//TODO: not sure, could be u64 or u32
typedef u64 pud_t;
typedef u64 pmd_t;
typedef u64 pt_t;

typedef u32 addr_t;
typedef u32 ul_t;
typedef s32 l_t;

#endif

#ifdef X86_64
/*
 * Maps to physical addr 0; #define __PAGE_OFFSET _AC(0xffff880000000000, UL)
 * inside arch/x86/include/asm/page_64_types.h.
 */
#define KERN			0xffff880000000000	
#define KERNEL_PGD		ctx->sym_addr[INIT_LEVEL4_PGT]

#define PGDIR_SHIFT     	39
#define PTRS_PER_PGD		512

#define PUD_SHIFT		30
#define PTRS_PER_PUD		512

#define PMD_SHIFT		21
#define PTRS_PER_PMD		512

#define PTRS_PER_PTE		512

#define PTR_SIZE		sizeof(u64)

#define __PHYSICAL_MASK_SHIFT	46

typedef u64 pgd_t;
typedef u64 pud_t;
typedef u64 pmd_t;
typedef u64 pt_t;

typedef u64 addr_t;
typedef u64 ul_t;
typedef s64 l_t;

#endif


struct double_link {
	addr_t next;
	addr_t prev;
};



#define PGDIR_SIZE		(1UL << PGDIR_SHIFT)
#define PGDIR_MASK		(~(PGDIR_SIZE - 1))

#define PUD_SIZE		(1UL << PUD_SHIFT)
#define PUD_MASK		(~(PUD_SIZE-1))

#define PMD_SIZE		(1UL << PMD_SHIFT)
#define PMD_MASK		(~(PMD_SIZE-1))

#define PAGE_SHIFT 		12
#define PAGE_SIZE		(1UL << PAGE_SHIFT)
#define PAGE_MASK 		(~(PAGE_SIZE-1))	//0xfffff000
#define PAGE_SIZE_KB		4

// only supporting 2MB / 4MB huge pages ... not x86_64's 1GB 
#define HPAGE_SHIFT		PMD_SHIFT
#define HPAGE_SIZE		(1UL << HPAGE_SHIFT)
#define HPAGE_MASK		(~(HPAGE_SIZE - 1))

// in binary, last 12 bits 0, all other bits 1 upto physical address bit count
#define PTE_PFN_MASK 		((pt_t) PHYSICAL_PAGE_MASK)
#define PHYSICAL_PAGE_MASK 	( ((l_t) PAGE_MASK) & __PHYSICAL_MASK )
#define __PHYSICAL_MASK		( (addr_t) (1ULL << __PHYSICAL_MASK_SHIFT) - 1 )
/*
 * PAGE_MASK turns an address into its page address.  PTE_PFN_MASK takes a pte
 * value and returns the pte's pfn portion (which is shifted so it's actually a
 * page address).  By Jeremy Fitzhardinge  at
 * https://lkml.org/lkml/2008/7/22/306
*/

#endif				// __TYPES_H__
