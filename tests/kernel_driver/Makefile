obj-m += syshook.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -o chardev chardev.c

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -rf chardev
