#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "process-list.h"

int main (int argc, char *argv[]) {
    int opt = 0;
    char *vm_name = NULL;
    char *mode = NULL;

    /**
     * Parsing Parameters
     * -v: vm name listed by xl list
     * -m: mode option
     */
    while ((opt = getopt(argc, argv, "v:m:h")) != -1) {
        switch(opt) {
            case 'h':
                printf("Usage: ./vmi -v [vm_name] -m [mode]\n");
                printf("Supported Mode: \n");
                printf("process-list: list the processes\n");
                return 0;
            case 'v':
                vm_name = optarg;
                break;
            case 'm':
                mode = optarg;
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
    }

    return 0;
}
