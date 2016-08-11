#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <Python.h>
#include <errno.h>
#include <stdlib.h>
#include <mntent.h>
#include <features.h>
#include <utmp.h>
#include <sched.h>
#include <linux/version.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <stdio.h>

#define USE_PTRACE	0

#include "psvmi_ctx.h"

int get_cpu_info(struct psvmi_context *ctx);
int get_os_info(struct psvmi_context *ctx, PyObject ** sysinfo,
		PyObject * addr_list);

int open_file(struct psvmi_context *ctx, FILE ** fd, char *suffix,
	      char *mode);
ul_t phy_mem_offset(ul_t base);
addr_t get_physical_addr(struct psvmi_context *ctx, addr_t virtualAddress,
			 pgd_t pgd);


void psvmi_context_init(struct psvmi_context *ctx,
			char *mem_dump_file,
			char *num_mem_chunks,
			char *qemu_pid,
			char *qemu_va_start,
			char *qemu_va_end,
			char *start_mem_addr,
			char *mem_size,
			PyObject * sys_map_list, PyObject * offset_list)
{
	ctx->hostname = NULL;
    ctx->kernel_version = NULL;
	//ctx->ip_addr_str = {'\0'};
	ctx->per_cpu_offset = NULL;
	ctx->last_inode_addr = 0;
	ctx->qemu_pid = -1;
	ctx->num_offsets = END_OFFSETS - START_OFFSETS;
	ctx->num_symbols = END_SYSMAP - START_SYSMAP;
	ctx->sym_val =
	    (int *) malloc(sizeof(unsigned int) * ctx->num_offsets);
	ctx->sym_addr =
	    (addr_t *) malloc(sizeof(addr_t) * ctx->num_symbols);

	ctx->mem_size = (u64) atol(mem_size);

	// should dec the reference if there is an error
	ctx->ret_list = PyList_New(0);
    ctx->ipaddr_list = NULL;
    ctx->interface_list = NULL;
    ctx->module_list = NULL;

	ctx->qemu_pid = atoi(qemu_pid);
	ctx->qemu_va_start = (u64) atol(qemu_va_start);
	ctx->qemu_va_end = (u64) atol(qemu_va_end);

	int i = 0;

#if USE_QEMU_VMEM == TRUE
	char qemu_mem_filename[255];
	sprintf(qemu_mem_filename, "/proc/%d/mem", ctx->qemu_pid);
	open_file(ctx, &ctx->fd, qemu_mem_filename, "rb");
#else
	open_file(ctx, &ctx->fd, argv[argIdx], "r");
#endif

	for (i = 0; i < ctx->num_symbols && sys_map_list; i++) {
		PyObject *strObj;
		strObj = PyList_GetItem(sys_map_list, i);
		sscanf(PyString_AsString(strObj), "%" FMT_LONG_X,
		       &ctx->sym_addr[i]);
	}

	// XXX it would be great to not get a hardcoded list, but a dic instead
	for (i = 0; i < ctx->num_offsets && offset_list; i++) {
		PyObject *strObj;
		strObj = PyList_GetItem(offset_list, i);
		ctx->sym_val[i] = atoi(PyString_AsString(strObj));
	}

    /*
    //with the version that reuses 'context', ptrace attach/detach would need to be made before
    //each individual fxn call and should't be here.
#if USE_PTRACE == TRUE
	ptrace(PTRACE_ATTACH, ctx->qemu_pid, NULL, NULL);
	waitpid(ctx->qemu_pid, NULL, 0);
#endif
    */
}

static PyObject* psvmi_context_init_wrapper(PyObject * self, PyObject * args)
{
	struct psvmi_context* ctx = malloc (sizeof(struct psvmi_context));
    char *mem_dump_file;
    char *num_mem_chunks;
    char *qemu_pid;
    char *qemu_va_start;
    char *qemu_va_end;
    char *start_mem_addr;
    char *mem_size;
    PyObject *sys_map_list; /* the list of strings */
    PyObject *offset_list;  /* the list of strings */

    if (!PyArg_ParseTuple
        (args, "sssssssOO", &mem_dump_file, &num_mem_chunks, &qemu_pid,
         &qemu_va_start, &qemu_va_end, &start_mem_addr, &mem_size,
         &sys_map_list, &offset_list)) {
        return NULL;
    }


	psvmi_context_init(ctx, mem_dump_file, num_mem_chunks,
			   qemu_pid, qemu_va_start, qemu_va_end,
			   start_mem_addr, mem_size, sys_map_list,
			   offset_list);
	
	// Create a capsule containing the context
    //PyObject* ctx1 = PyCapsule_New((void *)ctx, "ctx_wrapper", NULL);
    PyObject* ctx1 = PyCapsule_New((void *)ctx, NULL, NULL);

    /*
	//needed if ctx is to be reused across calls
#if USE_PTRACE == TRUE
    ptrace(PTRACE_DETACH, ctx->qemu_pid, NULL, NULL);
#endif
    */
	return ctx1;
}

struct psvmi_context* psvmi_get_context(PyObject* args)
{
    PyObject* ctx1;
    struct psvmi_context* ctx;
    
    if(!PyArg_ParseTuple(args, "O", &ctx1))
        return NULL;

    //ctx = (struct psvmi_context*) PyCapsule_GetPointer(ctx1,"ctx_wrapper");
    ctx = (struct psvmi_context*) PyCapsule_GetPointer(ctx1,NULL);

#if USE_PTRACE == TRUE
	ptrace(PTRACE_ATTACH, ctx->qemu_pid, NULL, NULL);
	waitpid(ctx->qemu_pid, NULL, 0);
#endif
 
    return ctx;
}

void psvmi_release_context(struct psvmi_context *ctx)
{
#if USE_PTRACE == TRUE
    ptrace(PTRACE_DETACH, ctx->qemu_pid, NULL, NULL);
#endif
}

void psvmi_context_destroy(struct psvmi_context *ctx)
{
#if USE_PTRACE == TRUE
	ptrace(PTRACE_DETACH, ctx->qemu_pid, NULL, NULL);
#endif

	fclose(ctx->fd);

#if EXTRACT_NW_INFO == 1
	if (nwinfofd != null)
		fclose(nwinfofd);
#endif
}


int read_elem(struct psvmi_context *ctx, void *buf, ul_t offset,
	      ul_t buf_size)
{
#if USE_QEMU_VMEM == TRUE
	/*
	 * For >=4G VMs there is a 512+8 MB gap int he BIOS RAM map after
	 * ~3.5G, so the kernel doesnt access that range for normal data and
	 * jumps this ~512MB to another "usable region" which is 512MB for 4G
	 * VM 1.5 GB for 5G VM, and 4.5 GB for an 8G VM.  But this hole does
	 * not exist in the virtual memory map inside /proc/pid/mem, so we
	 * subtract 512MB for >4G kernel addresses
	 */
	if (offset >= 0x100000000) {
		/*
		 * This should actually be offset = offset - (0x100000000 -
		 * 0xdfffe000) from RAM MAP, but for some reason last 8M is not
		 * accounted for.
		 */
		offset = (offset - 512 * 1024 * 1024);
	}

	u64 offset1 = ctx->qemu_va_start + offset;

	if (offset + buf_size >= ctx->qemu_va_end ||
	    offset1 + buf_size >= ctx->qemu_va_end) {
		goto invalid_offset;
	}

	if (fseeko(ctx->fd, offset1, SEEK_SET) == -1)
#else
	if (fseek(ctx->fd, offset, SEEK_SET) == -1)
#endif
	{
		perror("fseek");
		return -1;
	}

	fread(buf, buf_size, 1, ctx->fd);

	if (ferror(ctx->fd) != 0) {
		perror("fread");
		return -1;
	}

	return 0;

      invalid_offset:
	ERROR("Offset and/or size out of bounds:\n");
	ERROR("\tva_start=%" FMT_ULONG " va_end=%" FMT_ULONG "\n",
	      ctx->qemu_va_start, ctx->qemu_va_end);
	ERROR("\toffset=%" FMT_ULONG " buf_size=%" FMT_ULONG "\n",
	      offset1, buf_size);
	return -1;
}


int open_file(struct psvmi_context *ctx, FILE ** fd, char *suffix,
	      char *mode)
{
	char *filename;

	if (ctx->hostname == NULL) {
		filename = malloc(sizeof(char) * strlen(suffix));
		sprintf(filename, "%s", suffix);
	} else {
		filename =
		    malloc(sizeof(char) *
			   (strlen(ctx->hostname) +
			    strlen(ctx->ip_addr_str) + strlen(suffix) +
			    3));
		sprintf(filename, "%s_%s_%s", ctx->hostname,
			ctx->ip_addr_str, suffix);
	}

	*fd = fopen(filename, mode);
	if (*fd == NULL) {
		ERROR("error in %s file open\n", suffix);
		perror("fopen");
		return -1;
	}
	fseek(*fd, 0, SEEK_SET);

	return 0;
}


const char *get_module_state_str(struct psvmi_context *ctx,
				 unsigned int module_state)
{
	switch (module_state) {
	case 0:
		return "MODULE_STATE_LIVE";
	case 1:
		return "MODULE_STATE_COMING";
	case 2:
		return "MODULE_STATE_GOING";
	default:
		return "error";
	}

}


int get_module_list(struct psvmi_context *ctx)
{
	/*
	 * Modules lie in high memory region, need to traverse kernel page
	 * tables.
	 */

	struct double_link modules_list;
	char module_name[ctx->sym_val[MODULE_NAME_LEN]];
	unsigned int module_state;
	/* 
	 * The enum is indeed 4 bytes in 64 bit, but as a struct member it uses
	 * 8 bytes due to padding.
	 */
	addr_t highmem_pa, highmem_va;
	const char *module_state_str;

    //TODO: maybe free the previous list if creating a new one?
    //if(ctx->module_list == NULL)
            ctx->module_list = PyList_New(0);

	READ_ELEM(ctx, &modules_list, (ctx->sym_addr[MODULES]));

	while (1) {
		//term 'highmem; valid only for x86, simple VA for x86_64
		highmem_va = modules_list.next;
		highmem_pa =
		    get_physical_addr(ctx, highmem_va, KERNEL_PGD);

		if (highmem_pa == -1) {
			LOG("Error in get_physical_addr\n");
			return -1;
		}

		TEST_RET_VAL(read_elem
			     (ctx, &module_state,
			      highmem_pa -
			      ctx->sym_val[MODULE_LIST_HEAD_OFFSET] +
			      ctx->sym_val[MODULE_STATE_OFFSET],
			      sizeof(module_state)));
		module_state_str = get_module_state_str(ctx, module_state);

		TEST_RET_VAL(read_elem
			     (ctx, module_name,
			      highmem_pa -
			      ctx->sym_val[MODULE_LIST_HEAD_OFFSET] +
			      ctx->sym_val[MODULE_NAME_OFFSET],
			      sizeof(module_name)));

		TEST_RET_VAL(read_elem
			     (ctx, &modules_list,
			      highmem_pa - ctx->sym_val[LIST_HEAD_OFFSET] +
			      ctx->sym_val[LIST_HEAD_OFFSET],
			      sizeof(modules_list)));


        PyObject *module = 
            Py_BuildValue("ss", module_name, module_state_str);
        
        PyList_Append(ctx->module_list, module); 
		
        if (modules_list.next == ctx->sym_addr[MODULES]) {
			break;
		}
	}

	return 0;
}



const char *get_socket_type_str(short int sock_type)
{
	switch (sock_type) {
	case SOCK_STREAM:
		return "SOCK_STREAM";
	case SOCK_DGRAM:
		return "SOCK_DGRAM";
	case SOCK_RAW:
		return "SOCK_RAW";
	case SOCK_RDM:
		return "SOCK_RDM";
	case SOCK_SEQPACKET:
		return "SOCK_SEQPACKET";
	case SOCK_DCCP:
		return "SOCK_DCCP";
	case SOCK_PACKET:
		return "SOCK_PACKET";
	default:
		return "error";
	}
}


const char *get_socket_state_str(unsigned int sock_state)
{
	switch (sock_state) {
	case SS_FREE:
		return "SS_FREE";
	case SS_UNCONNECTED:
		return "SS_UNCONNECTED";
	case SS_CONNECTING:
		return "SS_CONNECTING";
	case SS_CONNECTED:
		return "SS_CONNECTED";
	case SS_DISCONNECTING:
		return "SS_DISCONNECTING";
	default:
		return "error";
	}
}


const char *get_socket_family_str(short unsigned int sock_family)
{
	switch (sock_family) {
	case AF_UNSPEC:
		return "AF_UNSPEC";
	case AF_UNIX:
		return "AF_UNIX";
	case AF_INET:
		return "AF_INET";
	case AF_INET6:
		return "AF_INET6";
	case AF_BRIDGE:
		return "AF_BRIDGE";
	case AF_NETLINK:
		return "AF_NETLINK";
	default:
		{
			char *ret_str = (char *) malloc(sizeof(char) * 6);
			sprintf(ret_str, "%u", sock_family);
			return ret_str;
		}
	}
}


char *make_ip_addr_str(unsigned int ip)
{
	char *ip_addr_str = (char *) malloc(255);
	unsigned char bytes[4];
	bytes[0] = ip & 0xFF;
	bytes[1] = (ip >> 8) & 0xFF;
	bytes[2] = (ip >> 16) & 0xFF;
	bytes[3] = (ip >> 24) & 0xFF;
	//sprintf(ip_addr_str, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1],
	//	bytes[0]);
	sprintf(ip_addr_str, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2],
		bytes[3]);
	return ip_addr_str;
}


// virtio_net driver
int get_virtio_net_stats(struct psvmi_context *ctx, addr_t net_device_addr, char* dev_name)
{
	addr_t virtnet_info_addr, virtnet_statsrc_addr,
	    per_cpu_virtnet_statsrc_addr;
	u64 tx_bytes = 0, tx_packets = 0, rx_bytes = 0, rx_packets =
	    0, tmp_ctr = 0, errout = -1, errin = -1;
	int i = 0;

	virtnet_info_addr =
	    net_device_addr + ctx->sym_val[NET_DEVICE_VIRTNET_INFO_OFFSET];
	READ_ELEM(ctx, &virtnet_statsrc_addr,
		  virtnet_info_addr +
		  ctx->sym_val[VIRTNET_INFO_VIRTNET_STATS_OFFSET]);

    if(ctx->per_cpu_offset == NULL)
        get_cpu_info(ctx);

	for (i = 0; i < ctx->num_cores; i++) {
		per_cpu_virtnet_statsrc_addr =
		    virtnet_statsrc_addr + ctx->per_cpu_offset[i];

		READ_ELEM(ctx, &tmp_ctr,
			  per_cpu_virtnet_statsrc_addr +
			  ctx->sym_val[VIRTNET_STATS_TX_BYTES_OFFSET]);
		tx_bytes += tmp_ctr;
		READ_ELEM(ctx, &tmp_ctr,
			  per_cpu_virtnet_statsrc_addr +
			  ctx->sym_val[VIRTNET_STATS_TX_PACKETS_OFFSET]);
		tx_packets += tmp_ctr;
		READ_ELEM(ctx, &tmp_ctr,
			  per_cpu_virtnet_statsrc_addr +
			  ctx->sym_val[VIRTNET_STATS_RX_BYTES_OFFSET]);
		rx_bytes += tmp_ctr;
		READ_ELEM(ctx, &tmp_ctr,
			  per_cpu_virtnet_statsrc_addr +
			  ctx->sym_val[VIRTNET_STATS_RX_PACKETS_OFFSET]);
		rx_packets += tmp_ctr;
	}

    PyObject *iface_stat = 
        Py_BuildValue("siiiiii", dev_name, tx_bytes, rx_bytes, tx_packets, rx_packets, errout, errin);
    
    PyList_Append(ctx->interface_list, iface_stat); 
	return 0;
}


// 8139cp driver
int get_generic_net_stats(struct psvmi_context *ctx,
			  addr_t net_device_addr, char* dev_name)
{
	addr_t statsrc_addr;
	ul_t tx_bytes = 0, tx_packets = 0, rx_bytes = 0, rx_packets = 0, errout = -1, errin = -1;

	statsrc_addr =
	    net_device_addr + ctx->sym_val[NET_DEVICE_STATS_OFFSET];
	//READ_ELEM(ctx, &statsrc_addr,
	//      net_device_addr + ctx->sym_val[NET_DEVICE_STATS_OFFSET]);

	READ_ELEM(ctx, &rx_packets,
		  statsrc_addr + ctx->sym_val[STATS_RX_PACKETS_OFFSET]);
	READ_ELEM(ctx, &tx_packets,
		  statsrc_addr + ctx->sym_val[STATS_TX_PACKETS_OFFSET]);
	READ_ELEM(ctx, &rx_bytes,
		  statsrc_addr + ctx->sym_val[STATS_RX_BYTES_OFFSET]);
	READ_ELEM(ctx, &tx_bytes,
		  statsrc_addr + ctx->sym_val[STATS_TX_BYTES_OFFSET]);

    
    PyObject *iface_stat = 
        Py_BuildValue("siiiiii", dev_name, tx_bytes, rx_bytes, tx_packets, rx_packets, errout, errin);
    
    PyList_Append(ctx->interface_list, iface_stat); 
    return 0;
}


int get_network_info(struct psvmi_context *ctx, /*unused*/PyObject* addr_list)
{

	struct double_link dev_base_list_head, dev_list;
	addr_t dev_base_list_head_addr, net_device_addr, dev_addrAddr,
	    ipInfoAddr, if_addr_list, if_addr;
	char dev_name[ctx->sym_val[NET_DEVICE_IFNAMSIZ]];
	char addr_len;
	char *dev_addr;
	unsigned int ip_addr, mask_addr, broadcast_addr;

    //if(ctx->ipaddr_list == NULL)
        ctx->ipaddr_list = PyList_New(0);

    //if(ctx->interface_list == NULL)
        ctx->interface_list = PyList_New(0);
	
    dev_base_list_head_addr =
	    ctx->sym_addr[INIT_NET] +
	    ctx->sym_val[NET_DEV_BASE_LIST_HEAD_OFFSET];
	READ_ELEM(ctx, &dev_base_list_head, dev_base_list_head_addr);
	net_device_addr =
	    dev_base_list_head.next -
	    ctx->sym_val[NET_DEVICE_DEV_LIST_OFFSET];

	while (1) {
		int addr_crawled = 0;
		READ_ELEM1(ctx, dev_name,
			   net_device_addr +
			   ctx->sym_val[NET_DEVICE_NAME_OFFSET]);

		READ_ELEM(ctx, &addr_len,
			  net_device_addr +
			  ctx->sym_val[NET_DEVICE_ADDR_LEN_OFFSET]);

		READ_ELEM(ctx, &dev_addrAddr,
			  net_device_addr +
			  ctx->sym_val[NET_DEVICE_DEV_ADDR_OFFSET]);

		dev_addr = (char *) malloc(sizeof(char) * addr_len);
		TEST_RET_VAL(read_elem
			     (ctx, dev_addr, phy_mem_offset(dev_addrAddr),
			      addr_len));

		READ_ELEM(ctx, &ipInfoAddr,
			  net_device_addr +
			  ctx->sym_val[NET_DEVICE_IN_DEVICE_OFFSET]);

		READ_ELEM(ctx, &if_addr_list,
			  ipInfoAddr +
			  ctx->sym_val[IN_DEVICE_IFADDR_LIST_OFFSET]);

		if_addr = if_addr_list;

		while (1) {
			if (if_addr == 0x0) {
				break;
			}

			addr_crawled++;
			READ_ELEM(ctx, &ip_addr,
				  if_addr +
				  ctx->sym_val[IFADDR_IPADDR_OFFSET]);
			READ_ELEM(ctx, &mask_addr,
				  if_addr +
				  ctx->sym_val[IFADDR_MASK_OFFSET]);
			READ_ELEM(ctx, &broadcast_addr,
				  if_addr +
				  ctx->sym_val[IFADDR_BROADCAST_OFFSET]);

			if (ip_addr != 0)
				strcpy(ctx->ip_addr_str,
				       make_ip_addr_str(ip_addr));

			PyObject *addr = NULL;
			addr =
			    Py_BuildValue("s", make_ip_addr_str(ip_addr));
			PyList_Append(ctx->ipaddr_list, addr);

			READ_ELEM(ctx, &if_addr,
				  if_addr +
				  ctx->sym_val[IFADDR_NEXT_OFFSET]);
		}


        //TODO: stats for loopback device (when not 0!) cannot be extracted by the 
        //current offsets. Need virtio style tricks for this. 
        //essentially, e.g. tx_bytes = sum(all cpus) lb_stats->bytes where
        //lb_stats = per_cpu_ptr(dev->lstats, i);
        //and dev = struct net_device* dev

        //TODO:this selection should actually depend upon which driver is loaded 
        //and not solely on which offsets are provided!
        //this can be figured out from the caller script by looking at
        //qemu process' flags (From ps)

        if(ctx->sym_val[NET_DEVICE_STATS_OFFSET] == -1)
		      get_virtio_net_stats(ctx, net_device_addr, dev_name);
		else
		      get_generic_net_stats(ctx, net_device_addr, dev_name);

		READ_ELEM(ctx, &dev_list,
			  net_device_addr +
			  ctx->sym_val[NET_DEVICE_DEV_LIST_OFFSET]);
		net_device_addr =
		    dev_list.next -
		    ctx->sym_val[NET_DEVICE_DEV_LIST_OFFSET];

		if (dev_list.next == dev_base_list_head_addr) {
			break;
		}
	}

	return 0;
}


int get_socket_info(struct psvmi_context *ctx, addr_t sock_addr,
		    PyObject ** conn)
{
	short unsigned int sock_type, sock_family, dst_port, src_port;
	unsigned int sock_state, dst_addr, src_addr;
	const char *sock_state_str;
	const char *sock_type_str;
	const char *sock_family_str;
	char *dst_addr_str;
	char *src_addr_str;

	READ_ELEM(ctx, &sock_state,
		  (sock_addr + ctx->sym_val[SOCKET_STATE_OFFSET]));
	sock_state_str = get_socket_state_str(sock_state);

	READ_ELEM(ctx, &sock_type,
		  (sock_addr + ctx->sym_val[SOCKET_TYPE_OFFSET]));
	sock_type_str = get_socket_type_str(sock_type);

	READ_ELEM(ctx, &sock_addr,
		  (sock_addr + ctx->sym_val[SOCKET_SOCK_OFFSET]));

	READ_ELEM(ctx, &dst_addr,
		  (sock_addr + ctx->sym_val[SOCK_DADDR_OFFSET]));
	dst_addr_str = make_ip_addr_str(dst_addr);

	READ_ELEM(ctx, &src_addr,
		  (sock_addr + ctx->sym_val[SOCK_SADDR_OFFSET]));
	src_addr_str = make_ip_addr_str(src_addr);

	READ_ELEM(ctx, &sock_family,
		  (sock_addr + ctx->sym_val[SOCK_FAMILY_OFFSET]));
	sock_family_str = get_socket_family_str(sock_family);

	READ_ELEM(ctx, &dst_port,
		  (sock_addr + ctx->sym_val[SOCK_DPORT_OFFSET]));
	dst_port = ((dst_port & 0xff) << 8) + ((dst_port >> 8) & 0xff);

	READ_ELEM(ctx, &src_port,
		  (sock_addr + ctx->sym_val[SOCK_SPORT_OFFSET]));

	if (sock_family == AF_INET || sock_family == AF_INET6)
		*conn = Py_BuildValue("issOOs", 0, sock_family_str,
				      sock_type_str, Py_BuildValue("(si)",
								   src_addr_str,
								   src_port),
				      Py_BuildValue("(si)", dst_addr_str,
						    src_port),
				      sock_state_str);

#if EXTRACT_NW_INFO == TRUE
	if (sock_family == AF_INET || sock_family == AF_INET6) {
		fprintf(nw_info_fd, "\n%s\t %16s\t %s\t %s:%u\t %s:%u",
			sock_family_str, sock_type_str, sock_state_str,
			src_addr_str, src_port, dst_addr_str, dst_port);
		log_nw_info = TRUE;
	}
#endif
	return 0;
}


char *get_filename(struct psvmi_context *ctx, addr_t fd_addr,
		   addr_t * _inode_addr)
{
#define MAX_PATHNAME_LEN 256
	unsigned char pathname[MAX_PATHNAME_LEN] = { '\0' };
	char *_pathname;
	unsigned int pathname_len = 1;
	unsigned int dentry_len;
	addr_t dentry_addr, inode_addr =
	    0, vfs_mount_addr, mountpoint_dentry_addr, dentry_name_addr,
	    dentry_parent_addr;
	int mountpoint_reached = -1;

	if (fd_addr != 0x0) {
		READ_ELEM(ctx, &vfs_mount_addr,
			  (fd_addr + ctx->sym_val[FD_PATH_OFFSET] +
			   ctx->sym_val[PATH_VFSMOUNT_OFFSET]));
		if (vfs_mount_addr == 0) {
			return NULL;
		}

		READ_ELEM(ctx, &mountpoint_dentry_addr,
			  (vfs_mount_addr +
			   ctx->sym_val
			   [VFSMOUNT_MOUNTPOINT_DENTRY_OFFSET]));
		if (mountpoint_dentry_addr == 0) {
			return NULL;
		}

		READ_ELEM(ctx, &dentry_addr,
			  (fd_addr + ctx->sym_val[FD_PATH_OFFSET] +
			   ctx->sym_val[PATH_DENTRY_OFFSET]));
		if (dentry_addr == 0) {
			return NULL;
		}

		READ_ELEM(ctx, &inode_addr,
			  (dentry_addr +
			   ctx->sym_val[DENTRY_INODE_OFFSET]));

		while (1) {

			READ_ELEM(ctx, &dentry_len,
				  (dentry_addr +
				   ctx->sym_val[DENTRY_LEN_OFFSET]));

			READ_ELEM(ctx, &dentry_name_addr,
				  (dentry_addr +
				   ctx->sym_val[DENTRY_NAME_OFFSET]));

			TEST_RET_VAL(read_elem
				     (ctx,
				      pathname + MAX_PATHNAME_LEN -
				      pathname_len - dentry_len,
				      phy_mem_offset(dentry_name_addr),
				      dentry_len));
			pathname_len += dentry_len;
			//pathname[MAX_PATHNAME_LEN - pathname_len - 1] =
			//    '/';
			//pathname_len += 1;

			READ_ELEM(ctx, &dentry_parent_addr,
				  (dentry_addr +
				   ctx->sym_val[DENTRY_PARENT_OFFSET]));

			if (dentry_parent_addr == dentry_addr) {
				if (mountpoint_reached == 0)
					break;
				else {
					dentry_addr =
					    mountpoint_dentry_addr;
					mountpoint_reached = 0;
				}
			} else
				dentry_addr = dentry_parent_addr;
		}
	}

	if (_inode_addr != NULL)
		*_inode_addr = inode_addr;
	_pathname = (char *) malloc(sizeof(char) * pathname_len);
	strncpy(_pathname,
		(char *) (pathname + MAX_PATHNAME_LEN - pathname_len),
		pathname_len);

	return _pathname;
}


// Some opened files are disk backed files, others are just sockets.
int get_open_files(struct psvmi_context *ctx, addr_t task_kva,
		   PyObject ** conn_list, PyObject ** files_list)
{
	int ret_val = 0;
	unsigned int max_fds, i;
	char *filename;
	short unsigned int inode_mode;

	addr_t files_addr, fdt_addr, fd_arr_addr, next_fdt_addr, fd_addr,
	    inode_addr;

	/*
	 * max_fds is an unsigned int, but on x86_64 under test, as a struct
	 * member it uses 8 bytes.
	 */

	READ_ELEM(ctx, &files_addr,
		  (task_kva + ctx->sym_val[FILES_OFFSET]));
	if (files_addr == 0) {
		return -1;
	}
	READ_ELEM(ctx, &fdt_addr, (files_addr + ctx->sym_val[FDT_OFFSET]));

	while (1) {
		READ_ELEM(ctx, &max_fds,
			  (fdt_addr + ctx->sym_val[MAX_FDS_OFFSET]));

		READ_ELEM(ctx, &fd_arr_addr,
			  (fdt_addr + ctx->sym_val[FD_ARR_OFFSET]));

		/*
		 * Kernels 3.13 and above do not have a next FD table. In
		 * fact, these kernels do not have a deferrable free FD
		 * tables.
		 */
		next_fdt_addr = 0;
		if (ctx->sym_val[NEXT_FDT_OFFSET] != -1)
			READ_ELEM(ctx, &next_fdt_addr,
				  (fdt_addr +
				   ctx->sym_val[NEXT_FDT_OFFSET]));

		for (i = 0; i < max_fds; i++) {
			READ_ELEM(ctx, &fd_addr,
				  (fd_arr_addr + i * sizeof(addr_t)));

			if (fd_addr == 0x0) {
				continue;
			}

			filename = get_filename(ctx, fd_addr, &inode_addr);

			// Means inode_addr is also most probably wrong.
			if (filename != NULL) {
				READ_ELEM(ctx, &inode_mode,
					  (inode_addr +
					   ctx->sym_val
					   [INODE_MODE_OFFSET]));

				if (S_ISSOCK(inode_mode)) {
					PyObject *conn = NULL;
					if (get_socket_info
					    (ctx,
					     inode_addr +
					     ctx->sym_val
					     [INODE_SOCKET_OFFSET],
					     &conn) == 1)
						ret_val = 1;
					if (conn != NULL)
						PyList_Append(*conn_list,
							      conn);
				} else {
					PyList_Append(*files_list,
						      Py_BuildValue("si",
								    filename,
								    i));
				}
				//free(filename);
			}
		}

		if (next_fdt_addr == 0x0)
			break;
		else
			fdt_addr = next_fdt_addr;
	}

	return ret_val;
}


char *get_full_command(struct psvmi_context *ctx, ul_t start_addr,
		       ul_t end_addr, addr_t pgd_addr)
{
	unsigned int i = 0;
	unsigned int str_len = end_addr - start_addr;
	char *ret_str = (char *) malloc(sizeof(char) * str_len);
	char *ret_str_refined = (char *) malloc(sizeof(char) * str_len);
	if (start_addr == 0 || end_addr == 0) {
		return ret_str;
	}
	addr_t start_pa = get_physical_addr(ctx, start_addr, pgd_addr);
	addr_t end_pa = get_physical_addr(ctx, end_addr - 1, pgd_addr);


	if (end_pa != start_pa + str_len - 1) {
		ret_str = strcpy(ret_str, (char *) "unknown");
	} else {
		/*
		 * Assumption: start and end addr would not cross page
		 * boundaries.
		 */
		TEST_RET_VAL(read_elem(ctx, ret_str, start_pa, str_len));

		for (i = 0; i < str_len; i++) {
			if (isprint(ret_str[i])) {
				ret_str_refined[i] = ret_str[i];
			} else {
				ret_str_refined[i] = ' ';
			}
		}
	}

	free(ret_str);
	ret_str_refined[str_len] = '\0';
	return ret_str_refined;
}


int get_process_memory_info(struct psvmi_context *ctx, addr_t task_kva,
			    PyObject ** command, ul_t *mem_vms, ul_t* mem_rss)
{
	addr_t mm_addr, vma_addr, pgd_addr, vma_next_addr,
	    vma_prev_addr, vma_file_addr, inode_addr, last_inode_addr =
	    (addr_t) (-1);
	ul_t total_vm_pages, vma_start_addr, vma_end_addr, vma_pg_off,
	    arg_start_addr, arg_end_addr;
	char *full_cmd_str;
	char *filename;
	l_t rss_stat[ctx->sym_val[NR_MM_COUNTERS]], rss_pages = 0, i = 0;

    *mem_vms = 0;
    *mem_rss = 0;

	ctx->last_inode_addr = last_inode_addr;
	READ_ELEM(ctx, &mm_addr,
		  (task_kva + ctx->sym_val[TASK_MM_OFFSET]));

	if (mm_addr == 0x0)
		return 1;

	while (1) {
		READ_ELEM(ctx, &vma_addr,
			  (mm_addr + ctx->sym_val[MM_VMA_OFFSET]));

		READ_ELEM(ctx, &pgd_addr,
			  (mm_addr + ctx->sym_val[MM_PGD_OFFSET]));

		READ_ELEM(ctx, &total_vm_pages,
			  (mm_addr + ctx->sym_val[MM_TOTAL_VM_OFFSET]));
        
        *mem_vms = total_vm_pages * PAGE_SIZE;

		READ_ELEM1(ctx, rss_stat,
			   (mm_addr + ctx->sym_val[MM_RSS_OFFSET]));

		READ_ELEM(ctx, &arg_start_addr,
			  (mm_addr + ctx->sym_val[MM_ARG_START_OFFSET]));

		READ_ELEM(ctx, &arg_end_addr,
			  (mm_addr + ctx->sym_val[MM_ARG_END_OFFSET]));

		for (i = 0, rss_pages = 0;
		     i < ctx->sym_val[NR_MM_COUNTERS] - 1; i++)
			rss_pages += (rss_stat[i] < 0 ? 0 : rss_stat[i]);

        *mem_rss = rss_pages * PAGE_SIZE;     

		full_cmd_str =
		    get_full_command(ctx, arg_start_addr, arg_end_addr,
				     pgd_addr);
		*command = Py_BuildValue("s", full_cmd_str);

		while (1) {
			READ_ELEM(ctx, &vma_start_addr,
				  (vma_addr +
				   ctx->sym_val[VMA_START_OFFSET]));
			READ_ELEM(ctx, &vma_end_addr,
				  (vma_addr +
				   ctx->sym_val[VMA_END_OFFSET]));
			READ_ELEM(ctx, &vma_next_addr,
				  (vma_addr +
				   ctx->sym_val[VMA_NEXT_OFFSET]));
			READ_ELEM(ctx, &vma_prev_addr,
				  (vma_addr +
				   ctx->sym_val[VMA_PREV_OFFSET]));
			READ_ELEM(ctx, &vma_file_addr,
				  (vma_addr +
				   ctx->sym_val[VMA_FILE_OFFSET]));
			READ_ELEM(ctx, &vma_pg_off,
				  (vma_addr +
				   ctx->sym_val[VMA_PGOFF_OFFSET]));
			filename = get_filename(ctx, vma_file_addr,
						&inode_addr);
			if (filename == NULL)
				return -1;

			free(filename);
			vma_addr = vma_next_addr;
			if (vma_addr == 0x0)
				break;
		}

		break;

	}

	return 0;
}


int get_process_sched_cpu_info(struct psvmi_context *ctx, addr_t task_addr)
{
	u64 sum_exec_runtime, wait_sum, io_wait_sum;

	if (ctx->sym_val[TASK_SCHEDENTITY_OFFSET] == -1
	    || ctx->sym_val[SCHEDENTITY_SCHEDSTATS_OFFSET] == -1) {
		return -1;
	} else {
		READ_ELEM(ctx, &sum_exec_runtime,
			  task_addr +
			  ctx->sym_val[TASK_SCHEDENTITY_OFFSET] +
			  ctx->sym_val[SCHEDENTITY_SUMEXECRUNTIME_OFFSET]);
		READ_ELEM(ctx, &wait_sum,
			  task_addr +
			  ctx->sym_val[TASK_SCHEDENTITY_OFFSET] +
			  ctx->sym_val[SCHEDENTITY_SCHEDSTATS_OFFSET] +
			  ctx->sym_val[SCHEDSTATS_WAITSUM_OFFSET]);
		READ_ELEM(ctx, &io_wait_sum,
			  task_addr +
			  ctx->sym_val[TASK_SCHEDENTITY_OFFSET] +
			  ctx->sym_val[SCHEDENTITY_SCHEDSTATS_OFFSET] +
			  ctx->sym_val[SCHEDSTATS_IOWAITSUM_OFFSET]);

		return 0;
	}

	return 0;
}

int correct_cputime_units(struct psvmi_context *ctx, l_t *process_cpu_time)
{
    //units of stime and utime changed from being jiffies to nanoseconds
    //https://lwn.net/Articles/623381/
    //so special cases to send jiffies back for easier cpu util calc inside py callers
    //i.e. psvmi or agentlessCrawler
    
    //this is only true for kernel versions >=3.15 (aug 2014 onwards) and ofcours 3.13 LTS
    //two options: 
    //1. based on kernel version read as input from caller
    //or a more stable option: i
    //2. if caller finds /include/linux/cputime.h in then do following else you got jiffies directly
    //if (process_cpu_time >= overall_cpu_time)
    
    //XXX: ugly hack, true only for ubuntu :(
    
    
    get_os_info(ctx, NULL, NULL);
    if (ctx->kernel_version == NULL)
    {    
        *process_cpu_time = -1; //safety first
        return -1;
    }

    //string tokenization here
    char *token = NULL;
    char* _myStr = ctx->kernel_version;
    int tokenInt[2]={0};
    int i = 0;
    for(i=0; i<2; i++)
    {
        token = strtok(_myStr, ".");
        if(token == NULL)
        {
            *process_cpu_time = -1; //safety first
            return -1;
        }
        tokenInt[i] = atoi(token);
        _myStr = NULL;
    }

    int major_kernel_version = tokenInt[0], minor_kernel_version = tokenInt[1];
  
    //essentially playing it safe, not supporting 3.13 3.14
    //could do better, for ex. get_os_info can also tell if its ubuntu/fedora etc. 
    //so can be more specific (more ugly_ in this hack

    int cputime_to_jiffies = FALSE;
    switch(major_kernel_version)
    {
        case 2: 
                break;
        case 3:
                if(minor_kernel_version == 13 || minor_kernel_version == 14)
                    *process_cpu_time = -1;

                if(minor_kernel_version >=15)
                    cputime_to_jiffies = TRUE;

                break;    
        case 4: 
                cputime_to_jiffies = TRUE;
                break;
        default:   *process_cpu_time = -1;        
                    break;
    }

    if(cputime_to_jiffies == TRUE)
    {
        //nanoseconds -> jiffies
        if(ctx->sym_val[CONFIG_HZ] == -1)
            *process_cpu_time = -1;    //can't convert without HZ value!
        else
            *process_cpu_time = *process_cpu_time * ctx->sym_val[CONFIG_HZ] / 1000000000;
    }
    return 0;
}


int get_task_list(struct psvmi_context *ctx)
{
	struct double_link task_list;
	addr_t task_addr, parent_task_addr;
	unsigned int pid, ppid;
	char task_name[ctx->sym_val[TASK_COMM_LEN]];
	int exit_state = 0;
    ul_t state = 0; //TASK_RUNNING    
    ul_t mem_vms = 0, mem_rss = 0;
	PyObject *tuple = NULL;
    u64 overall_cpu_time = 0;
    ul_t stime = 0, utime = 0;
    l_t process_cpu_time = 0;
    ul_t startTime[2] = {0};

    ctx->ret_list = PyList_New(0);

    if (ctx->sym_addr[JIFFIES_64] != -1)
    {
        READ_ELEM(ctx, &overall_cpu_time,
            ctx->sym_addr[JIFFIES_64]);
    }

	READ_ELEM(ctx, &task_list,
		  (ctx->sym_addr[INIT_TASK] +
		   ctx->sym_val[LIST_HEAD_OFFSET]));
	READ_ELEM(ctx, &pid,
		  (ctx->sym_addr[INIT_TASK] + ctx->sym_val[PID_OFFSET]));

	READ_ELEM(ctx, &parent_task_addr,
		  (ctx->sym_addr[INIT_TASK] +
		   ctx->sym_val[REAL_PARENT_OFFSET]));
	READ_ELEM(ctx, &ppid,
		  (parent_task_addr + ctx->sym_val[PID_OFFSET]));

	READ_ELEM1(ctx, task_name,
		   (ctx->sym_addr[INIT_TASK] + ctx->sym_val[COMM_OFFSET]));


	//kva: kernel virtual address

	tuple = Py_BuildValue("(isssksisOOiiilk)", pid, task_name,
			      "unknown", "unknown", startTime[0], "unknown",
			      ppid, "unknown", PyList_New(0),
			      PyList_New(0), mem_rss, mem_vms, state, process_cpu_time, overall_cpu_time);
	PyList_Append(ctx->ret_list, tuple);
	Py_DECREF(tuple);

	while (1) {
		PyObject *tuple = NULL;
#if EXTRACT_NW_INFO == TRUE
		log_nw_info = FALSE;
#endif
		task_addr =
		    task_list.next - ctx->sym_val[LIST_HEAD_OFFSET];
		if (task_addr == ctx->sym_addr[INIT_TASK])
			break;

        if (ctx->sym_val[STATE_OFFSET] != -1)
        {    
		    READ_ELEM(ctx, &state,
			    (task_addr + ctx->sym_val[STATE_OFFSET]));
        }

		READ_ELEM(ctx, &pid,
			  (task_addr + ctx->sym_val[PID_OFFSET]));

		READ_ELEM(ctx, &parent_task_addr,
			  (task_addr + ctx->sym_val[REAL_PARENT_OFFSET]));
		READ_ELEM(ctx, &ppid,
			  (parent_task_addr + ctx->sym_val[PID_OFFSET]));

		READ_ELEM1(ctx, task_name,
			   (task_addr + ctx->sym_val[COMM_OFFSET]));

        //cpu time only being accounted for a process, not its threads
        //for multi threaded procs, need to add utime and stime from threads as well
        //need offset for  thread_group structure inside task_struct
        READ_ELEM(ctx, &utime, task_addr + ctx->sym_val[TASK_UTIME_OFFSET]);
        READ_ELEM(ctx, &stime, task_addr + ctx->sym_val[TASK_STIME_OFFSET]);
        process_cpu_time = utime + stime;
  
        correct_cputime_units(ctx, &process_cpu_time);
        
        READ_ELEM(ctx, &startTime, task_addr + ctx->sym_val[TASK_START_TIME_OFFSET]);

		if (ctx->sym_val[EXITSTATE_OFFSET] != -1)
			READ_ELEM(ctx, &exit_state,
				  (task_addr +
				   ctx->sym_val[EXITSTATE_OFFSET]));

		PyObject *conn_list = PyList_New(0);
		PyObject *files_list = PyList_New(0);
		PyObject *command = Py_BuildValue("s", "command");
		READ_ELEM(ctx, &task_list,
			  (task_list.next -
			   ctx->sym_val[LIST_HEAD_OFFSET] +
			   ctx->sym_val[LIST_HEAD_OFFSET]));
		if (exit_state == 0) {
			// exit_state != 0 => task is zombie (16) / dead (32)
			get_open_files(ctx, task_addr, &conn_list,
				       &files_list);
			get_process_memory_info(ctx, task_addr, &command, &mem_vms, &mem_rss);
			get_process_sched_cpu_info(ctx, task_addr);
		}
		if (command == NULL)
			command = Py_BuildValue("s", "unknown");

		tuple = Py_BuildValue("(isOsksisOOiiilk)", pid, task_name,
				      command, "unknown", startTime[0], "unknown",
				      ppid, "unknown", conn_list,
				      files_list, mem_rss, mem_vms, state, process_cpu_time, overall_cpu_time);
		PyList_Append(ctx->ret_list, tuple);
		Py_DECREF(tuple);

	}

	return 0;
}


enum zone_stat_item {
	/* First 128 byte cacheline (assuming 64 bit words) */
	NR_FREE_PAGES,
	NR_LRU_BASE,
	NR_INACTIVE_ANON = NR_LRU_BASE,	/* must match order of LRU_[IN]ACTIVE */
	NR_ACTIVE_ANON,		/*  "     "     "   "       "         */
	NR_INACTIVE_FILE,	/*  "     "     "   "       "         */
	NR_ACTIVE_FILE,		/*  "     "     "   "       "         */
	NR_UNEVICTABLE,		/*  "     "     "   "       "         */
	NR_MLOCK,		/* mlock()ed pages found and moved off LRU */
	NR_ANON_PAGES,		/* Mapped anonymous pages */
	NR_FILE_MAPPED,		/* pagecache pages mapped into pagetables.
				   only modified from process context */
	NR_FILE_PAGES,
	NR_FILE_DIRTY,
	NR_WRITEBACK,
	NR_SLAB_RECLAIMABLE,
	NR_SLAB_UNRECLAIMABLE,
	NR_PAGETABLE,		/* used for pagetables */
	NR_KERNEL_STACK
};


int get_cpu_info(struct psvmi_context *ctx)
{
	//short unsigned int ctx->num_cores;
	unsigned int cpu_khz, cpu_cache_size_kb;
	unsigned char cpu_family, cpu_vendor, cpu_model;
	char cpu_vendor_id[16], cpu_model_id[64];
	u64 cpu_time = 0;

	READ_ELEM(ctx, &cpu_khz, (ctx->sym_addr[CPU_KHZ]));
	READ_ELEM(ctx, &cpu_family,
		  (ctx->sym_addr[BOOT_CPU_DATA] +
		   ctx->sym_val[CPUINFO_FAMILY_OFFSET]));
	READ_ELEM(ctx, &cpu_vendor,
		  (ctx->sym_addr[BOOT_CPU_DATA] +
		   ctx->sym_val[CPUINFO_VENDOR_OFFSET]));
	READ_ELEM(ctx, &cpu_model,
		  (ctx->sym_addr[BOOT_CPU_DATA] +
		   ctx->sym_val[CPUINFO_MODEL_OFFSET]));
	READ_ELEM1(ctx, cpu_vendor_id,
		   (ctx->sym_addr[BOOT_CPU_DATA] +
		    ctx->sym_val[CPUINFO_VENDOR_ID_OFFSET]));
	READ_ELEM1(ctx, cpu_model_id,
		   (ctx->sym_addr[BOOT_CPU_DATA] +
		    ctx->sym_val[CPUINFO_MODEL_ID_OFFSET]));
	READ_ELEM(ctx, &cpu_cache_size_kb,
		  (ctx->sym_addr[BOOT_CPU_DATA] +
		   ctx->sym_val[CPUINFO_CACHE_SIZE_OFFSET]));

	//READ_ELEM(ctx, &ctx->num_cores,
	//        (ctx->sym_addr[BOOT_CPU_DATA] +
	//         ctx->sym_val[CPUINFO_MAX_CORES_OFFSET]));

	READ_ELEM(ctx, &ctx->num_cores, (ctx->sym_addr[NUM_PROCESSORS]));

	ctx->per_cpu_offset =
	    (ul_t *) malloc(sizeof(ul_t) * ctx->num_cores);
	TEST_RET_VAL(read_elem
		     (ctx, ctx->per_cpu_offset,
		      phy_mem_offset(ctx->sym_addr[__PER_CPU_OFFSET]),
		      sizeof(ul_t) * ctx->num_cores));

	READ_ELEM(ctx, &cpu_time, ctx->sym_addr[JIFFIES_64]);
	
    ctx->cpuHwinfo = Py_BuildValue("(bbbssiii)",
				 cpu_family,
				 cpu_vendor,
                 cpu_model,
                 cpu_vendor_id,
                 cpu_model_id,
				 cpu_khz,
				 cpu_cache_size_kb,
                 ctx->num_cores);

	return 0;
}


int get_os_info(struct psvmi_context *ctx, PyObject ** sysinfo,
		PyObject * addr_list)
{

//TODO: why do we need these hardcoded sizes here, NEW_UTSNAME_LEN is already 64 from the offsets file, and that should suffice: Ohttp://lxr.free-electrons.com/source/include/uapi/linux/utsname.h#L24
#define UTS_MAX_NAME_SIZE		65
#define UTS_MAX_OSNAME_SIZE 	132

	unsigned char uts_name[ctx->sym_val[NEW_UTSNAME_LEN] + 1];
	int i = 0;
	int num_uts_name_elems = 6;
	char sysname[UTS_MAX_NAME_SIZE]={0};
	char nodename[UTS_MAX_NAME_SIZE]={0};
	char release[UTS_MAX_NAME_SIZE]={0};
	char version[UTS_MAX_NAME_SIZE]={0};
	char machine[UTS_MAX_NAME_SIZE]={0};
	char osname[UTS_MAX_OSNAME_SIZE]={0};

	for (i = 0; i < num_uts_name_elems; i++) {
		READ_ELEM1(ctx, uts_name, (ctx->sym_addr[INIT_UTS_NS] +
					   ctx->sym_val[NS_UTSNAME_OFFSET]
					   +
					   i *
					   (ctx->sym_val[NEW_UTSNAME_LEN] +
					    1)));

		switch (i) {
		case 0:
			strncpy(sysname, (char *) uts_name,
				UTS_MAX_NAME_SIZE - 1);
			break;
		case 1:
			ctx->hostname =
			    (char *) malloc(sizeof(char) *
					    ctx->sym_val[NEW_UTSNAME_LEN] +
					    1);
			strncpy(ctx->hostname, (char *) uts_name,
				ctx->sym_val[NEW_UTSNAME_LEN]);
			strncpy(nodename, (char *) uts_name,
				UTS_MAX_NAME_SIZE - 1);
			break;
		case 2:
			strncpy(release, (char *) uts_name,
				UTS_MAX_NAME_SIZE - 1);
            ctx->kernel_version = release;
			break;
		case 3:
			strncpy(version, (char *) uts_name,
				UTS_MAX_NAME_SIZE - 1);
			break;
		case 4:
			strncpy(machine, (char *) uts_name,
				UTS_MAX_NAME_SIZE - 1);
			break;
		// ignoring case 5:domainname
		default:
			break;
		}
	}

    if(sysinfo != NULL)
    {
	    *sysinfo = Py_BuildValue("(sOssssss)",//iiii)",
				 "unknown",
				 addr_list,
				 "unknown",
				 osname,
				 machine,
				 release,
				 sysname,
				 version);
    }
	return 0;
}

int get_system_memory_info(struct psvmi_context *ctx, PyObject ** meminfo)
{
	ul_t total_ram_pages=0, free_ram_pages=0, buffered_pages=0, cached_pages=0;
	
    READ_ELEM(ctx, &total_ram_pages,
		  (ctx->sym_addr[TOTALRAM_PAGES]));
	READ_ELEM(ctx, &free_ram_pages,
		  (ctx->sym_addr[VM_STAT] +
		   ctx->sym_val[VM_STAT_FREE_PAGES_OFFSET]));

    /*
    //XXX: the following don't map to /proc/meminfo's defintion of buffered/cached
    //which is what psutil uses     
	READ_ELEM(ctx, &buffered_pages,
		  (ctx->sym_addr[VM_STAT] + sizeof(long) * NR_FILE_PAGES));
	READ_ELEM(ctx, &cached_pages,
		  (ctx->sym_addr[VM_STAT] +
		   sizeof(long) * NR_ACTIVE_FILE));
    */

    //until the proper offsets are figured out
    buffered_pages = -1;
    cached_pages = -1;
    
    *meminfo = Py_BuildValue("(iiiii)",
                 total_ram_pages * PAGE_SIZE_KB,
                 (total_ram_pages -
                 free_ram_pages) * PAGE_SIZE_KB,
                 buffered_pages * PAGE_SIZE_KB,
                 cached_pages * PAGE_SIZE_KB,
                 free_ram_pages * PAGE_SIZE_KB);

    return 0;             
}

// https://code.google.com/p/psutil/source/browse/psutil/_psutil_linux.c
static PyObject *psvmi_get_processes(PyObject * self, PyObject * args)
{
    struct psvmi_context* ctx = psvmi_get_context(args);

    if (ctx == NULL) return NULL;

	get_task_list(ctx);

    psvmi_release_context(ctx);

	return ctx->ret_list;
}

// https://code.google.com/p/psutil/source/browse/psutil/_psutil_linux.c
static PyObject *psvmi_get_processes_deprecated(PyObject * self, PyObject * args)
{
	struct psvmi_context ctx;
	char *mem_dump_file;
	char *num_mem_chunks;
	char *qemu_pid;
	char *qemu_va_start;
	char *qemu_va_end;
	char *start_mem_addr;
	char *mem_size;
	PyObject *sys_map_list;	/* the list of strings */
	PyObject *offset_list;	/* the list of strings */

	if (!PyArg_ParseTuple(args, "sssssssOO",
			      &mem_dump_file, &num_mem_chunks,
			      &qemu_pid, &qemu_va_start, &qemu_va_end,
			      &start_mem_addr, &mem_size, &sys_map_list,
			      &offset_list)) {
		goto error;
	}

	psvmi_context_init(&ctx, mem_dump_file, num_mem_chunks,
			   qemu_pid, qemu_va_start, qemu_va_end,
			   start_mem_addr, mem_size, sys_map_list,
			   offset_list);

	get_task_list(&ctx);
	psvmi_context_destroy(&ctx);

	return ctx.ret_list;
      error:
	return NULL;
}

static PyObject *psvmi_read_mem_as_text(PyObject * self, PyObject * args)
{
	char *string = NULL;
	struct psvmi_context ctx;
	char *mem_dump_file;
	char *num_mem_chunks;
	char *qemu_pid;
	char *qemu_va_start;
	char *qemu_va_end;
	char *start_mem_addr;
	char *mem_size;
	unsigned long long int start, end;
	int len;

	if (!PyArg_ParseTuple(args, "ssssssskk",
			      &mem_dump_file, &num_mem_chunks,
			      &qemu_pid, &qemu_va_start, &qemu_va_end,
			      &start_mem_addr, &mem_size, &start, &end)) {
		goto error;
	}

	len = (int) (end - start);
	string = malloc(len);

	psvmi_context_init(&ctx, mem_dump_file, num_mem_chunks,
			   qemu_pid, qemu_va_start, qemu_va_end,
			   start_mem_addr, mem_size, NULL, NULL);

	read_elem(&ctx, string, phy_mem_offset(start), len);
	psvmi_context_destroy(&ctx);

	int j;
	for (j = 0; j < len; j++) {
		if (string[j] < 32 || string[j] >= 127)
			string[j] = ' ';
	}

	PyObject *strObj;

	strObj = PyString_FromStringAndSize(string, len);
	free(string);

	return strObj;

      error:
	return NULL;
}


// https://code.google.com/p/psutil/source/browse/psutil/_psutil_linux.c

static PyObject *psvmi_system_info_deprecated(PyObject * self, PyObject * args)
{
	struct psvmi_context ctx;
	char *mem_dump_file;
	char *num_mem_chunks;
	char *qemu_pid;
	char *qemu_va_start;
	char *qemu_va_end;
	char *start_mem_addr;
	char *mem_size;
	PyObject *sys_map_list;	/* the list of strings */
	PyObject *offset_list;	/* the list of strings */

	ctx.ret_list = PyList_New(0);

	if (!PyArg_ParseTuple
	    (args, "sssssssOO", &mem_dump_file, &num_mem_chunks, &qemu_pid,
	     &qemu_va_start, &qemu_va_end, &start_mem_addr, &mem_size,
	     &sys_map_list, &offset_list)) {
		goto error;
	}

	psvmi_context_init(&ctx, mem_dump_file, num_mem_chunks,
			   qemu_pid, qemu_va_start, qemu_va_end,
			   start_mem_addr, mem_size, sys_map_list,
			   offset_list);

	PyObject *addr_list = PyList_New(0);

	 get_cpu_info(&ctx);
	/*
	 * XXX
	 * addr_list is passed so get_os_info can pack the pyobject
	 * with the list of ips. Same for memory info.
	 * */
	get_os_info(&ctx, &ctx.sysinfo, addr_list);
	get_network_info(&ctx, addr_list);
#if EXTRACT_NW_INFO == TRUE
	open_file(&ctx, &nw_info_fd, "NW_INFO", "w");
#endif
	get_module_list(&ctx);

	psvmi_context_destroy(&ctx);

	return ctx.sysinfo;

      error:
	//Py_XDECREF(sysinfo);
	return NULL;
}

static PyObject *psvmi_system_info(PyObject * self, PyObject * args)
{
	struct psvmi_context* ctx = psvmi_get_context(args);

    if (ctx == NULL) return NULL;

    if(ctx->ipaddr_list == NULL)
        get_network_info(ctx, /*arg unused*/ctx->ipaddr_list);

	get_os_info(ctx, &(ctx->sysinfo), ctx->ipaddr_list);

    psvmi_release_context(ctx);

	return ctx->sysinfo;

}

static PyObject *psvmi_cpuHw_info(PyObject * self, PyObject * args)
{
	struct psvmi_context* ctx = psvmi_get_context(args);

    if (ctx == NULL) return NULL;

	get_cpu_info(ctx);

    psvmi_release_context(ctx);

	return ctx->cpuHwinfo;

}

static PyObject *psvmi_module_list(PyObject * self, PyObject * args)
{
	struct psvmi_context* ctx = psvmi_get_context(args);

    if (ctx == NULL) return NULL;

    get_module_list(ctx);

    psvmi_release_context(ctx);

	return ctx->module_list;

}

static PyObject *psvmi_interface_list(PyObject * self, PyObject * args)
{
	struct psvmi_context* ctx = psvmi_get_context(args);

    if (ctx == NULL) return NULL;

    //stats could have changed in succesive iterations so need to re-crawl
    //ideally need to re-crawl only stats instead of everything
    //if(ctx->interface_list == NULL)
        get_network_info(ctx, /*arg unused*/ctx->ipaddr_list);

    psvmi_release_context(ctx);

	return ctx->interface_list;

}

static PyObject *psvmi_system_memory_info(PyObject * self, PyObject * args)
{
	struct psvmi_context* ctx = psvmi_get_context(args);

    if (ctx == NULL) return NULL;

    PyObject* meminfo;

	get_system_memory_info(ctx, &meminfo);

    psvmi_release_context(ctx);

	return meminfo;
}


static PyMethodDef PsvmiMethods[] = {
	{"get_processes", psvmi_get_processes, METH_VARARGS,
	 "Get the list of running processes."},
	{"system_info", psvmi_system_info, METH_VARARGS,
	 "Get system information."},
	{"system_memory_info", psvmi_system_memory_info, METH_VARARGS,
	 "Get system memory information."},
	{"interface_list", psvmi_interface_list, METH_VARARGS,
	 "Get list of nw infaces with stats"},
	{"module_list", psvmi_module_list, METH_VARARGS,
	 "Get list of loaded modules"},
	{"cpuHw_info", psvmi_cpuHw_info, METH_VARARGS,
	 "Get cpu hw info- make, model"},
	{"read_mem_as_text", psvmi_read_mem_as_text, METH_VARARGS,
	 "Return the printable memory contents at the given range."},
	//{"get_cpu_hw", psvmi_get_cpu_hw, METH_VARARGS,
	//"Get hw config of cpu"},
	{"context_init", psvmi_context_init_wrapper, METH_VARARGS,
	"initialize psvmi context."},
	{NULL, NULL, 0, NULL}	/* Sentinel */
};

PyMODINIT_FUNC init_psvmi(void)
{
	(void) Py_InitModule("_psvmi", PsvmiMethods);
}

int main(int argc, char *argv[])
{
	/* Pass argv[0] to the Python interpreter */
	Py_SetProgramName(argv[0]);

	/* Initialize the Python interpreter.  Required. */
	Py_Initialize();

	/* Add a static module */
	init_psvmi();

	return 0;
}
