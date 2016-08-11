import psvmi
import sys

# Test script that prints the list of processes and system info for a kvm guest

_vm_name = sys.argv[1]
_qemu_pid = sys.argv[2]
_kernel_version = sys.argv[3]
_distro = sys.argv[4]
_arch = sys.argv[5]
RUNNING_VM = sys.argv[6]


vm_context = psvmi.context_init(qemu_pid=_qemu_pid, kernel_version=_kernel_version, distro=_distro, arch=_arch)

output = psvmi.system_info(vm_context)
assert 'Linux' in output
assert len(list(output)) > 0

output = psvmi.cpuHw_info(vm_context)
assert 'QEMU' in str(output)
assert len(list(output)) > 0

output = psvmi.interface_iter(vm_context)
assert any('lo' in i for i in output)

output = psvmi.module_iter(vm_context)
assert len(list(output))>0    

if RUNNING_VM is -1:
    output = psvmi.process_iter(vm_context)
    assert any('psvmi_test_init' in i.name() for i in output)

for p in psvmi.process_iter(vm_context):
    if p.pid == 0:
        assert 'swapper' in str(p.name())
    
    elif p.name() == 'psvmi_test_init':
        assert p.get_memory_info().rss > 0
        assert p.get_memory_info().vms > 0 
        assert p.get_memory_percent() > 0
        assert list(p.get_cpu_times())[1] > 0
        assert 'fd=0' in str(p.get_open_files())
        assert 'devconsole' in str(p.get_open_files())
        
    else:
        assert p.pid > 0

print "Test passed" + str(sys.argv)
#test_psvmi('<INSTANCE>', '4.0.3.x86_64', 'vanilla', "x86_64")
#test_psvmi('<INSTANCE>', '3.2.0-101-generic_3.2.0-101.x86_64', 'ubuntu', 'x86_64')
#test_psvmi('24882', '3.2.0-101-generic_3.2.0-101.x86_64', 'ubuntu', 'x86_64')

