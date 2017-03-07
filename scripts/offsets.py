# flake8: noqa

import numpy

LENGTH = 1
OFFSET = 2
CONST  = 3
VALUE  = 4
RAW    = 5

items = [
	[ "NS_UTSNAME_OFFSET",  [[OFFSET, "struct uts_namespace",  "name"]] ],
	#[ "NEW_UTSNAME_LEN",  [["struct new_utsname",  "sysname"]] ],
	[ "NEW_UTSNAME_LEN",  [[RAW, "printf \"NEW_UTSNAME_LEN %d\n\", sizeof(((struct new_utsname*)0x0).sysname) - 1",  ""]] ],

	[ "CPUINFO_FAMILY_OFFSET",  [[OFFSET, "struct cpuinfo_x86",  "x86"]] ],
	[ "CPUINFO_VENDOR_OFFSET",  [[OFFSET, "struct cpuinfo_x86",  "x86_vendor"]] ],
	[ "CPUINFO_MODEL_OFFSET",  [[OFFSET, "struct cpuinfo_x86",  "x86_model"]] ],
	[ "CPUINFO_VENDOR_ID_OFFSET",  [[OFFSET, "struct cpuinfo_x86",  "x86_vendor_id"]] ],
	[ "CPUINFO_MODEL_ID_OFFSET",  [[OFFSET, "struct cpuinfo_x86",  "x86_model_id"]] ],
	[ "CPUINFO_CACHE_SIZE_OFFSET",  [[OFFSET, "struct cpuinfo_x86",  "x86_cache_size"]] ],
	[ "CPUINFO_MAX_CORES_OFFSET",  [[OFFSET, "struct cpuinfo_x86",  "x86_max_cores"]] ],
	[ "VM_STAT_FREE_PAGES_OFFSET",  [[VALUE, "0", ""]] ],
	
	[ "LIST_HEAD_OFFSET",  [[OFFSET, "struct task_struct",  "tasks"]] ],
	[ "COMM_OFFSET",  [[OFFSET, "struct task_struct",  "comm"]] ],
	[ "PID_OFFSET",  [[OFFSET, "struct task_struct",  "pid"]] ],
	[ "REAL_PARENT_OFFSET",  [[OFFSET, "struct task_struct",  "real_parent"]] ],
	[ "TASK_COMM_LEN",  [[LENGTH, "struct task_struct",  "comm"]] ],

	[ "TASK_UTIME_OFFSET",  [[OFFSET, "struct task_struct",  "utime"]] ],
	[ "TASK_STIME_OFFSET",  [[OFFSET, "struct task_struct",  "stime"]] ],
	[ "TASK_START_TIME_OFFSET",  [[OFFSET, "struct task_struct",  " start_time"]] ],
	[ "TASK_REAL_START_TIME_OFFSET",  [[OFFSET, "struct task_struct",  "real_start_time"]] ],

	[ "NR_CPUUSAGE_STATS",  [[RAW, "printf \"NR_CPUUSAGE_STATS %d\n\", sizeof(((struct kernel_cpustat*)0x0).cpustat) / 8",  ""],
                                 [RAW, "printf \"NR_CPUUSAGE_STATS %d\n\", sizeof(((struct kernel_stat*)0x0).cpustat) / 8",  ""]] ],

	[ "TASK_MM_OFFSET",  [[OFFSET, "struct task_struct",  "mm"]] ],
	[ "MM_VMA_OFFSET",  [[OFFSET, "struct mm_struct",  "mmap"]] ],
	[ "MM_ARG_START_OFFSET",  [[OFFSET, "struct mm_struct",  "arg_start"]] ],
	[ "MM_ARG_END_OFFSET",  [[OFFSET, "struct mm_struct",  "arg_end"]] ],
	[ "MM_PGD_OFFSET",  [[OFFSET, "struct mm_struct",  "pgd"]] ],
	[ "MM_LIST_HEAD_OFFSET",  [[OFFSET, "struct mm_struct",  "mmlist"]] ],
	[ "MM_TOTAL_VM_OFFSET",  [[OFFSET, "struct mm_struct",  "total_vm"]] ],
	[ "MM_RSS_OFFSET",  [[OFFSET, "struct mm_struct",  "rss_stat"], [OFFSET, "struct mm_struct", "_file_rss"]] ],
	[ "NR_MM_COUNTERS", [[VALUE, "3", ""]] ],

	[ "VMA_START_OFFSET",  [[OFFSET, "struct vm_area_struct",  "vm_start"]] ],
	[ "VMA_END_OFFSET",  [[OFFSET, "struct vm_area_struct",  "vm_end"]] ],
	[ "VMA_NEXT_OFFSET",  [[OFFSET, "struct vm_area_struct",  "vm_next"]] ],
	[ "VMA_PREV_OFFSET",  [[OFFSET, "struct vm_area_struct",  "vm_prev"]] ],
	[ "VMA_FILE_OFFSET",  [[OFFSET, "struct vm_area_struct",  "vm_file"]] ],
	[ "VMA_PGOFF_OFFSET",  [[OFFSET, "struct vm_area_struct",  "vm_pgoff"]] ],

	[ "FILES_OFFSET",  [[OFFSET, "struct task_struct",  "files"]] ],
	[ "FDT_OFFSET",  [[OFFSET, "struct files_struct",  "fdt"]] ],
	[ "MAX_FDS_OFFSET",  [[OFFSET, "struct fdtable",  "max_fds"]] ],
	[ "FD_ARR_OFFSET",  [[OFFSET, "struct fdtable",  "fd"]] ],
	[ "NEXT_FDT_OFFSET",  [[OFFSET, "struct fdtable",  "next"]] ], # Kernels 3.13 and above do not have a next FD table.
	[ "FD_PATH_OFFSET",  [[OFFSET, "struct file",  "f_path"]] ],

	[ "PATH_VFSMOUNT_OFFSET",  [[OFFSET, "struct path",  "mnt"]] ],

	[ "VFSMOUNT_MOUNTPOINT_DENTRY_OFFSET",  [[OFFSET, "struct vfsmount",  "mnt_mountpoint"],
                                                 [RAW, "printf \"VFSMOUNT_MOUNTPOINT_DENTRY_OFFSET %d\n\","
                                                       "(int) &(((struct mount*)0x0).mnt_mountpoint) - (int) &(((struct mount*)0x0).mnt.mnt_root)",  ""]] ],
	[ "PATH_DENTRY_OFFSET",  [[OFFSET, "struct path",  "dentry"]] ],
	[ "DENTRY_PARENT_OFFSET",  [[OFFSET, "struct dentry",  "d_parent"]] ],
	[ "DENTRY_INODE_OFFSET",  [[OFFSET, "struct dentry",  "d_inode"]] ],
	[ "DENTRY_LEN_OFFSET",  [[OFFSET, "struct dentry",  "d_name.len"]] ],
	[ "DENTRY_NAME_OFFSET",  [[OFFSET, "struct dentry",  "d_name.name"]] ],
	[ "INODE_MODE_OFFSET",  [[OFFSET, "struct inode",  "i_mode"]] ],

	[ "INODE_SOCKET_OFFSET",  [[RAW, "printf \"INODE_SOCKET_OFFSET %d\n\","
                                         "(int) &(((struct socket_alloc*)0x0).socket) - (int) &(((struct socket_alloc*)0x0).vfs_inode)", ""]] ],

	[ "SOCKET_STATE_OFFSET",  [[OFFSET, "struct socket",  "state"]] ],
	[ "SOCKET_TYPE_OFFSET",  [[OFFSET, "struct socket",  "type"]] ],
	[ "SOCKET_SOCK_OFFSET",  [[OFFSET, "struct socket",  "sk"]] ],
	[ "SOCK_DADDR_OFFSET",  [[OFFSET, "struct inet_sock",  "inet.daddr"],
                                 [OFFSET, "struct inet_sock",  "inet_daddr"],
                                 [OFFSET, "struct inet_sock",  "daddr"],
                                 [OFFSET, "struct inet_sock",  "sk.__sk_common.skc_daddr"]] ],
	[ "SOCK_SADDR_OFFSET",  [[OFFSET, "struct inet_sock",  "inet.rcv_saddr"],
                                 [OFFSET, "struct inet_sock",  "inet_rcv_saddr"],
                                 [OFFSET, "struct inet_sock",  "rcv_saddr"],
                                 [OFFSET, "struct inet_sock",  "sk.__sk_common.skc_rcv_saddr"]] ],
	[ "SOCK_FAMILY_OFFSET", [[OFFSET, "struct sock",  "__sk_common.skc_family"],
                                 [OFFSET, "struct inet_sock",  "sk.__sk_common.skc_family"]] ],
	[ "SOCK_DPORT_OFFSET",  [[OFFSET, "struct inet_sock", "inet.dport"],
                                 [OFFSET, "struct inet_sock",  "inet_dport"],
                                 [OFFSET, "struct inet_sock",  "dport"],
                                 [OFFSET, "struct inet_sock",  "sk.__sk_common.skc_dport"]] ],
	[ "SOCK_SPORT_OFFSET",  [[OFFSET, "struct inet_sock", "inet.num"],
                                 [OFFSET, "struct inet_sock",  "inet_num"],
                                 [OFFSET, "struct inet_sock",  "sk.__sk_common.skc_num"],
                                 [OFFSET, "struct inet_sock",  "num"]] ],

	[ "MODULE_STATE_OFFSET",  [[OFFSET, "struct module",  "state"]] ],
	[ "MODULE_LIST_HEAD_OFFSET",  [[OFFSET, "struct module",  "list"]] ],
	[ "MODULE_NAME_OFFSET",  [[OFFSET, "struct module",  "name"]] ],
	[ "MODULE_NAME_LEN",  [[LENGTH, "struct module",  "name"]] ],

	[ "NET_DEV_BASE_LIST_HEAD_OFFSET",  [[OFFSET, "struct net", "dev_base_head"]] ],
	[ "NET_DEVICE_SIZE",  [[RAW, "printf \"NET_DEVICE_SIZE %d\n\", sizeof(struct net_device)",  ""]] ],
	[ "NET_DEVICE_DEV_LIST_OFFSET",  [[OFFSET, "struct net_device",  "dev_list"]] ],
	[ "NET_DEVICE_NAME_OFFSET",  [[OFFSET, "struct net_device",  "name"]] ],
	[ "NET_DEVICE_IFNAMSIZ",  [[LENGTH, "struct net_device",  "name"]] ],
	[ "NET_DEVICE_ADDR_LEN_OFFSET",  [[OFFSET, "struct net_device",  "addr_len"]] ],
	[ "NET_DEVICE_DEV_ADDR_OFFSET",  [[OFFSET, "struct net_device",  "dev_addr"]] ],
	[ "NET_DEVICE_IN_DEVICE_OFFSET",  [[OFFSET, "struct net_device",  "ip_ptr"]] ],
	[ "IN_DEVICE_IFADDR_LIST_OFFSET",  [[OFFSET, "struct in_device",  "ifa_list"]] ],
	[ "IFADDR_NEXT_OFFSET",  [[OFFSET, "struct in_ifaddr",  "ifa_next"]] ],
	[ "IFADDR_IPADDR_OFFSET",  [[OFFSET, "struct in_ifaddr",  "ifa_address"]] ],
	[ "IFADDR_MASK_OFFSET",  [[OFFSET, "struct in_ifaddr",  "ifa_mask"]] ],
	[ "IFADDR_BROADCAST_OFFSET",  [[OFFSET, "struct in_ifaddr",  "ifa_broadcast"]] ],

	[ "NET_DEVICE_STATS_OFFSET",  [[OFFSET, "struct net_device",  "stats"]] ],
	[ "STATS_TX_BYTES_OFFSET",  [[OFFSET, "struct net_device_stats",  "tx_bytes"]] ],
	[ "STATS_TX_PACKETS_OFFSET",  [[OFFSET, "struct net_device_stats",  "tx_packets"]] ],
	[ "STATS_RX_BYTES_OFFSET",  [[OFFSET, "struct net_device_stats",  "rx_bytes"]] ],
	[ "STATS_RX_PACKETS_OFFSET",  [[OFFSET, "struct net_device_stats",  "rx_packets"]] ],

#	[ "NET_DEVICE_VIRTNET_INFO_OFFSET",  [["printf \"NET_DEVICE_VIRTNET_INFO_OFFSET %d\n\", sizeof(struct net_device)",  ""]] ],
#	[ "VIRTNET_INFO_VIRTNET_STATS_OFFSET",  [["struct virtnet_info",  "stats"]] ],
#	[ "VIRTNET_STATS_TX_BYTES_OFFSET",  [["struct virtnet_stats",  "tx_bytes"]] ],
#	[ "VIRTNET_STATS_TX_PACKETS_OFFSET",  [["struct virtnet_stats",  "tx_packets"]] ],
#	[ "VIRTNET_STATS_RX_BYTES_OFFSET",  [["struct virtnet_stats",  "rx_bytes"]] ],
#	[ "VIRTNET_STATS_RX_PACKETS_OFFSET",  [["struct virtnet_stats",  "rx_packets"]] ],
]
	

def offset_cmd(key, struct, field):
	try:
		gdb.execute("printf \"" + key + " %d\\n\", &(((" +
                            struct + "*)0x0)." + field + ")")
		return 1
	except:
		return 0

def length_cmd(key, struct, field):
	try:
		gdb.execute("printf \"" + key + " %d\\n\", sizeof(((" +
                            struct + "*)0x0)." + field + ")")
		return 1
	except:
		return 0

def value_cmd(key, value, na):
	print(key + " " + value)
	return 1

def const_cmd(key, struct, field):
	try:
		gdb.execute("printf \"" + key + " %d\\n\"," + struct)
		#gdb.execute("info macro " + struct)
		#gdb.execute("macro expand " + struct)
		return 1
	except:
		return 0

def raw_cmd(key, cmd, na):
	try:
		gdb.execute(cmd)
		return 1
	except:
		return 0



command =  { OFFSET: offset_cmd,
	     LENGTH: length_cmd,
	     CONST:  const_cmd,
	     VALUE:  value_cmd,
	     RAW:    raw_cmd }

for item in items:
	found = 0
	key = item[0]
	for cmd in item[1]:
		cmd_type   = cmd[0]
		cmd_struct = cmd[1]
		cmd_field  = cmd[2]
		if (command[cmd_type](key, cmd_struct, cmd_field) == 1):
			found = 1
			break
	if (found == 0):
		print(key + " " + "-1")
