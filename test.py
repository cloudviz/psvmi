import psvmi

# Test script that prints the list of processes and system info for a kvm guest
KERNEL = "3.13.0-83-generic"
KERNEL_LONG = "3.13.0-83.127"
ARCH = "x86_64"
INSTANCE = "25738"

# This is ubuntu kernel version format
KERNEL_VERSION = '{0}_{1}.{2}'.format(KERNEL, KERNEL_LONG, ARCH)

for p in psvmi.process_iter(qemu_pid=INSTANCE, kernel_version=KERNEL_VERSION, distro='ubuntu', arch=ARCH):
    print(p.name(), p.pid, p.get_connections(), p.get_open_files())
print('')
print(psvmi.system_info(qemu_pid=INSTANCE, kernel_version=KERNEL_VERSION, distro='ubuntu', arch=ARCH))
