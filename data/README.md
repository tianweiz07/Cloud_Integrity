data
=======

This folder contains data for VMI. Move them to the same folder with the executable


blacklist.txt
------

This file contains the program's name, and its MD5 hash values, which will be blocked

It is used by:
	process-block
	sleepapi-nop


syscall\_index
------

This file stores the mapping between the index and syscall name.

It is used by:
	syscall-check
	syscall-trace
