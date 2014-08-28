obj-m += dhcp6-hook.o

PWD:=$(shell pwd)

KERNDIR:=/lib/modules/$(shell uname -r)/build/

default :
	$(MAKE) -C $(KERNDIR) M=$(PWD) modules

install :
	$(MAKE) -C $(KERNDIR) M=$(PWD) modules_install
	depmod -a
clean :
	$(MAKE) -C $(KERNDIR) M=$(PWD) clean

