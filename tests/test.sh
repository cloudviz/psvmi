#!/bin/bash

# start a VM that does pretty much nothing: just runs our dummy init() that
# loops forever

qemu-system-x86_64 \
	-kernel tests/vanilla/4.0.3.x86_64/vmlinuz \
	-append 'init=psvmi_test_init root=/dev/sda console=ttyAMA0  console=ttyS0' \
	-m 512 \
	-smp 1 \
	-drive format=raw,file=tests/disk.qcow2 \
	-serial stdio | while read LOGLINE
do
	[[ "${LOGLINE}" == *"Mounted root"* ]] && \
	sleep 3 && \
	sed -i "s/<INSTANCE>/9/g" tests/test.py && \
	python2.7 tests/test.py && pkill -P $$ qemu
done

exit 0
