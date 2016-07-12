#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <inttypes.h>
#include <signal.h>

#include <libvmi/libvmi.h>
#include <libvmi/events.h>

static int interrupted = 0;

vmi_event_t syscall_sysenter_event;
vmi_event_t single_event;

reg_t lstar;
addr_t phys_lstar;

uint32_t orig_data;
vmi_pid_t pid = -1;


event_response_t single_step_cb(vmi_instance_t vmi, vmi_event_t *event) {

    syscall_sysenter_event.interrupt_event.reinject = 1;
    if (set_breakpoint(vmi, lstar, 0) < 0) {
        fprintf(stderr, "Could not set break points\n");
        exit(1);
    }
    
    vmi_clear_event(vmi, &single_event, NULL);
    return 0;
}


event_response_t syscall_sysenter_cb(vmi_instance_t vmi, vmi_event_t *event){
    reg_t rdi, rax, cr3;
    vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rdi, RDI, event->vcpu_id);
    vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);

    if (event->interrupt_event.gla == lstar) {
        pid = vmi_dtb_to_pid(vmi, cr3);
        /* Here is the problem: it is hard for you to know whether the parameter is 
           an int, a pointer to a string, or any other types. 
           how to distinguish the types of first parameter? */
        if (rax == 90 ) {
            char *argname = NULL;
            argname = vmi_read_str_va(vmi, rdi, pid);
            printf("Process[%d]: Syscall happened: RAX(syscall#)=%u RDI(1st argument)=%s\n", pid, (unsigned int)rax, argname);
        }
        else
            printf("Process[%d]: Syscall happened: RAX(syscall#)=%u RDI(1st argument)=%u\n", pid, (unsigned int)rax, (unsigned int)rdi);
    }

    event->interrupt_event.reinject = 0;
    if (VMI_FAILURE == vmi_write_32_va(vmi, lstar, 0, &orig_data)) {
        fprintf(stderr, "failed to write memory.\n");
        exit(1);
    }

    vmi_register_event(vmi, &single_event);
    return 0;
}

int set_breakpoint(vmi_instance_t vmi, addr_t addr, pid_t pid) {

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

static void close_handler(int sig){
    interrupted = sig;
}

int main (int argc, char **argv) {

    if(argc < 2){
        fprintf(stderr, "Usage: events_example <name of VM> <PID of process to track {optional}>\n");
        exit(1);
    }

    char *name = NULL;
    name = argv[1];

    struct sigaction act;
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    vmi_instance_t vmi = NULL;
    if (vmi_init(&vmi, VMI_XEN | VMI_INIT_COMPLETE | VMI_INIT_EVENTS, name) == VMI_FAILURE){
        printf("Failed to init LibVMI library.\n");
        if (vmi != NULL )
            vmi_destroy(vmi);
        return 1;
    }
    else
        printf("LibVMI init succeeded!\n");


    vmi_get_vcpureg(vmi, &lstar, MSR_LSTAR, 0);

    phys_lstar = vmi_translate_kv2p(vmi,lstar);

    memset(&syscall_sysenter_event, 0, sizeof(vmi_event_t));
    syscall_sysenter_event.type = VMI_EVENT_INTERRUPT;
    syscall_sysenter_event.interrupt_event.intr = INT3;
    syscall_sysenter_event.callback = syscall_sysenter_cb;

    memset(&single_event, 0, sizeof(vmi_event_t));
    single_event.type = VMI_EVENT_SINGLESTEP;
    single_event.callback = single_step_cb;
    single_event.ss_event.enable = 1;
    SET_VCPU_SINGLESTEP(single_event.ss_event, 0);

    if (VMI_FAILURE == vmi_read_32_va(vmi, lstar, 0, &orig_data)) {
        printf("failed to read memory.\n");
        vmi_destroy(vmi);
        return -1;
    }

    if(vmi_register_event(vmi, &syscall_sysenter_event) == VMI_FAILURE) {
        fprintf(stderr, "Could not install sysenter syscall handler.\n");
        goto leave;
    }

    if (set_breakpoint(vmi, lstar, 0) < 0) {
        fprintf(stderr, "Could not set break points\n");
        goto leave;
    }

    status_t status;
    while(!interrupted){
        status = vmi_events_listen(vmi, 1000);
        if (status != VMI_SUCCESS) {
            printf("Error waiting for events, quitting...\n");
            interrupted = -1;
        }
    }
    printf("Finished with test.\n");

leave:
    if (VMI_FAILURE == vmi_write_32_va(vmi, lstar, 0, &orig_data)) {
        fprintf(stderr, "failed to write memory.\n");
        exit(1);
    }

    vmi_destroy(vmi);

    return 0;
}
