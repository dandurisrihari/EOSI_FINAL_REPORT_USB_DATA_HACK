


IOT_HOME = /opt/iot-devkit/1.7.2/sysroots
PWD:= $(shell pwd)

KDIR:=$(IOT_HOME)/i586-poky-linux/usr/src/kernel
PATH := $(PATH):$(IOT_HOME)/x86_64-pokysdk-linux/usr/bin/i586-poky-linux

CC = i586-poky-linux-gcc
ARCH = x86
CROSS_COMPILE = i586-poky-linux-
SROOT=$(IOT_HOME)/i586-poky-linux/

APP1 = info_tester
CFLAGS+ = -g -Wall

obj-m = info_stealer.o

all:
	make EXTRA_FLAGS=$(CFLAGS) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KDIR) M=$(PWD) modules
	$(CC) -o $(APP1) main.c -Wall -g --sysroot=$(SROOT)
clean:
	make ARCH=x86 CROSS_COMPILE=i586-poky-linux- -C $(SROOT)/usr/src/kernel M=$(PWD) clean
	rm -f *.ko
	rm -f *.o
	rm -f Module.symvers
	rm -f modules.order
	rm -f *.mod.c
	rm -rf .tmp_versions
	rm -f *.mod.c
	rm -f *.mod.o
	rm -f \.*.cmd
	rm -f Module.markers
	rm -f $(APP1) 

