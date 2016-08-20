VMI
=======


Introduction
------

This tool uses Virtual Machine Introspection to detect rootkits, trace syscall/APIs, 
and control VMs' code path to prevent it from being compromised by malware.


Requirements
------

The following software are required:

- Xen: the newer version of Xen hypervisor is recommanded (e.g., Xen-4.7)

- Libvmi: this is a C library for virtual machine introspection. 

For hardware, this tool uses hardware virtualization extensions found in Intel CPUs.
So we need an Intel CPU with virtualization support (VT-x) and with Extended Page Tables 
(EPT). 


Supported guests
------

We test the codes on Linux 2.6, 64-bit versions. 


Usage
------

To compile the source code, just type "make" at the root directory. It will generate a vmi
binary.

To run the program, use the following command:
    ./vmi -v [vm-name] -m [mode]

The vm-name is the name of the introspected VM, displayed by the hypervisor (e.g., xl list)

We support the following mode:

- process-list:           List the processes
- module-list:            List the modules
- syscall-check:          Check if any syscall is hooked
- idt-check:	          Check if any interrupt handler is hooked
- network-check:          Check if any network connection is hidden
- syscall-trace:          Trace the system call made by any processes
- socketapi-trace:        Trace the socket API made by any processes
- driverapi-trace:	  Trace the kernel device driver API made by any processes
- process-block:          Block a process from launching if its image matches something
- sleepapi-nop:           NOP the sleep calls to specified processes
- process-kill:           Kill a process given its pid


tools
------

This folder provides a set of tools to find the offsets of the linux kernel structure. Copy
this folder into the guest OS, compile and insert the kernel modules into the guest kernel.
You will get the offsets from dmesg. Then you can feed the offsets into the libvmi.conf, or
into the source code. 


tests
------

This folder provides several testing programs:

- rootkits: this folder gives three rootkits for detecting.
- syscall: a simple program, using some syscalls for tracing
- kernel\_driver: registering a Character device for detection
- net\_socket: establishing a network socket for detection
- sleep: a program calling sleep APIs. 

