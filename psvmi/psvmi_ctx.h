#ifndef _PSVMI_CTX_H_
#define _PSVMI_CTX_H_


#include <Python.h>
#include "header.h"

struct psvmi_context {
	FILE *fd;
	char *hostname;
    char* kernel_version;
	char ip_addr_str[16];
	unsigned int num_cores;
	u64 mem_size;
	ul_t *per_cpu_offset;
	int *sym_val;
	addr_t *sym_addr;
	addr_t last_inode_addr;
	u64 qemu_va_start;
	u64 qemu_va_end;
	int qemu_pid;
	int num_offsets;
	int num_symbols;
	PyObject *ret_list;
	PyObject *sysinfo;
    PyObject *ipaddr_list;
    PyObject *interface_list;
    PyObject *module_list;
    PyObject *cpuHwinfo;
};

#endif
