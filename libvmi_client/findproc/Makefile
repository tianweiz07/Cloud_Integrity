obj-m +=findproc.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules -lcsys

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
