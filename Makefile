KERNEL_TREE_PATH?=/lib/modules/$(shell uname -r)/build

obj-m := vmlaunch_simple.o

all: vmlaunch_simple.ko

vmlaunch_simple.ko: vmlaunch_simple.c
	make -C $(KERNEL_TREE_PATH) M=$(PWD) modules

clean:
	make -C $(KERNEL_TREE_PATH) M=$(PWD) clean

.PHONY: all clean
