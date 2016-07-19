#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/mman.h>

#include <libvmi/libvmi.h>

/**
 * default is using INT 3 for event notification
 * if MEM_EVENT is defined, then using EPT violation
 */
#define MEM_EVENT


int introspect_process_list(char *name);

int introspect_module_check(char *name);

int introspect_syscall_check(char *name);

int introspect_network_check(char *name);
