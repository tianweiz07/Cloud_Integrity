#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <openssl/md5.h>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>

/**
 * default is using INT 3 for event notification
 * if MEM_EVENT is defined, then using EPT violation
 */

#define MEM_EVENT


/* task_struct offsets */
unsigned long tasks_offset;
unsigned long pid_offset;
unsigned long name_offset;


static int set_breakpoint(vmi_instance_t vmi, addr_t addr, pid_t pid) {

    uint32_t data;
    if (VMI_FAILURE == vmi_read_32_va(vmi, addr, pid, &data)) {
        printf("failed to read memory.\n");
        return -1;
    }
    data = (data & 0xFFFFFF00) | 0xCC;
    if (VMI_FAILURE == vmi_write_32_va(vmi, addr, pid, &data)) {
        printf("failed to write memory.\n");
        return -1;
    }
    return 0;
}

static int interrupted = 0;

static void close_handler(int sig){
    interrupted = sig;
}

int introspect_process_list(char *name);

int introspect_module_list(char *name);

int introspect_syscall_check(char *name);

int introspect_kernel_check(char *name);

int introspect_idt_check(char *name);

int introspect_network_check(char *name);

int introspect_procfs_check(char *name);

int introspect_syscall_trace(char *name);

int introspect_socketapi_trace(char *name);

int introspect_driverapi_trace(char *name);

int introspect_sleepapi_nop(char *name);

int introspect_process_block(char *name);

int introspect_process_kill(char *name, char *arg);
