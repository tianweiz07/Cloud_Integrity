#include "vmi.h"

int main (int argc, char *argv[]) {
    int opt = 0;
    char *vm_name = NULL;
    char *mode = NULL;
    char *arg = NULL;

    /**
     * Parsing Parameters
     * -v: vm name listed by xl list
     * -m: mode option
     */
    while ((opt = getopt(argc, argv, "v:m:r:h")) != -1) {
        switch(opt) {
            case 'h':
                printf("Usage: ./vmi -v [vm_name] -m [mode]\n");
                printf("Supported Mode: \n");
                printf("process-list:		List the processes\n");
                printf("module-list:		List the modules\n");
                printf("syscall-check:		Check if any syscall is hooked\n");
                printf("idt-check:		Check if any interrupt handler is hooked\n");
                printf("network-check:		Check if any network connection is hidden\n");
                printf("syscall-trace:		Trace the system call made by any processes\n");
                printf("socketapi-trace:	Trace the socket API made by any processes\n");
                printf("driverapi-trace:	Trace the kernel device driver API made by any processes\n");
                printf("process-block:		Block a process from launching if its image matches something\n");
                printf("sleepapi-nop:		NOP the sleep calls to specified processes\n");
                printf("process-kill:		Kill a process at runtime given its pid\n");
                return 0;
            case 'v':
                vm_name = optarg;
                break;
            case 'm':
                mode = optarg;
                break;
            case 'r':
                arg = optarg;
                break;
            case '?':
                if (optopt == 'v') {
                    printf("Missing mandatory VM name option\n");
                } else if (optopt == 'm') {
                    printf("Missing mandatory Mode option\n");
                } else {
                    printf("Invalid option received\n");
                }
                break;
        }
    }

    if ((!vm_name) || (!mode)) {
        printf("Missing mandatory VM name or Mode option\n");
        return 0;
    } 


    printf("Introspect VM %s with the Mode %s\n", vm_name, mode);

    if (!strcmp(mode, "process-list")) {
        introspect_process_list(vm_name);
    } else if (!strcmp(mode, "module-list")) {
        introspect_module_list(vm_name);
    } else if (!strcmp(mode, "syscall-check")) {
        introspect_syscall_check(vm_name);
    } else if (!strcmp(mode, "idt-check")) {
        introspect_idt_check(vm_name);
    } else if (!strcmp(mode, "network-check")) {
        introspect_network_check(vm_name);
    } else if (!strcmp(mode, "syscall-trace")) {
        introspect_syscall_trace(vm_name);
    } else if (!strcmp(mode, "socketapi-trace")) {
        introspect_socketapi_trace(vm_name);
    } else if (!strcmp(mode, "driverapi-trace")) {
        introspect_driverapi_trace(vm_name);
    } else if (!strcmp(mode, "process-block")) {
        introspect_process_block(vm_name);
    } else if (!strcmp(mode, "sleepapi-nop")) {
        introspect_sleepapi_nop(vm_name);
    } else if (!strcmp(mode, "process-kill")) {
        if (arg == NULL) {
            printf("Missing process id to kill\n");
            return 0;
        }
        introspect_process_kill(vm_name, arg);
    } else {
        printf("Mode %s is not supported\n", mode);
    }

    return 0;
}
