#!/bin/bash

# start a VM that does pretty much nothing: just runs our dummy init() that
# loops forever

RUNNING_VM=-1

create_offset_file()
{
    local kernel_version=$1 #4.0.3.x86_64

    wget -nc https://sourceforge.net/projects/psvmi/files/vmlinux-${kernel_version}

    # Only create the offsets file if there is something actually downloaded
    if [ $? -eq 0 ]
    then
        (cd scripts; gdb --batch -x offsets.gdb -s ../vmlinux-${kernel_version} > \
            ../offsets/vanilla/x86_64/offsets_${kernel_version})
    fi
}

test_crawl()
{
    local vm_name=$1
    local kernel_version=$2
    local os_type=$3
    local arch=$4

    qemu_pid=`ps ax | grep -i qemu | grep "name $vm_name " | grep -v grep |  awk '{print $1}'`
    
    echo "" ; echo "Starting test" $@
    python2.7 tests/test.py $vm_name $qemu_pid $kernel_version $os_type $arch $RUNNING_VM 
}

create_vm_and_test_crawl()
{
    local vm_name=$1
    local kernel_version=$2
    local os_type=$3
    local arch=$4
    
    qemu-system-x86_64 \
        -kernel tests/vmlinuz/vmlinuz-$kernel_version \
        -append 'init=psvmi_test_init root=/dev/sda console=ttyAMA0  console=ttyS0' \
        -name $vm_name \
        -m 512 \
        -smp 1 \
        -drive format=raw,file=tests/disk.qcow2 \
        -vnc :1 \
        -serial stdio | while read LOGLINE
	do
		[[ "${LOGLINE}" == *"Mounted root"* ]] && \
		sleep 3 && \
        test_crawl $vm_name $kernel_version $os_type $arch && \
        pkill -P $$ qemu
	done
}

# Just vmlinux 4.0.3.x86_64 is uploaded at the moment. There is already an offset
# file for all the other ones.
create_offset_file 4.0.3.x86_64

if [ $1 == 'RUNNING_VM' ]
then
    #change the following params to match your running VM
    RUNNING_VM=1
    test_crawl 'vm2' '3.2.0-101-generic_3.2.0-101.x86_64' 'ubuntu' 'x86_64'
else
    create_vm_and_test_crawl 'vm2' '4.0.3.x86_64' 'vanilla' 'x86_64'
    create_vm_and_test_crawl 'vm3' '3.2.0-101-generic_3.2.0-101.x86_64' 'ubuntu' 'x86_64'
    create_vm_and_test_crawl 'vm4' '3.13.0-24-generic_3.13.0-24.x86_64' 'ubuntu' 'x86_64'
fi

exit 0
