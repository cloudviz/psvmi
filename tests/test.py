import psvmi

# Test script that prints the list of processes and system info for a kvm guest
ARCH = "x86_64"
INSTANCE = '<INSTANCE>'
KERNEL_VERSION = '4.0.3.x86_64'

print(
    psvmi.system_info(
        qemu_pid=INSTANCE,
        kernel_version=KERNEL_VERSION,
        distro='vanilla',
        arch=ARCH))

for p in psvmi.process_iter(
        qemu_pid=INSTANCE,
        kernel_version=KERNEL_VERSION,
        distro='vanilla', arch=ARCH):
    print(p.name(), p.pid)  # , p.get_connections(), p.get_open_files()
