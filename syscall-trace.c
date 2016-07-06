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


event_response_t single_step_cb(vmi_instance_t vmi, vmi_event_t *event) {

    vmi_register_event(vmi, &syscall_sysenter_event);
    vmi_clear_event(vmi, &single_event, NULL);
    return 0;
}


event_response_t syscall_sysenter_cb(vmi_instance_t vmi, vmi_event_t *event){
    reg_t rdi, rax;
    vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rdi, RDI, event->vcpu_id);

    if (event->mem_event.gla == lstar)
        printf("Syscall happened: RAX(syscall#)=%u RDI(1st argument)=%u\n", (unsigned int)rax, (unsigned int)rdi);


    vmi_clear_event(vmi, event, NULL);
    vmi_register_event(vmi, &single_event);
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
    syscall_sysenter_event.type = VMI_EVENT_MEMORY;
    syscall_sysenter_event.mem_event.physical_address = phys_lstar;
    syscall_sysenter_event.mem_event.npages = 1;
    syscall_sysenter_event.mem_event.granularity = VMI_MEMEVENT_PAGE;
    syscall_sysenter_event.mem_event.in_access = VMI_MEMACCESS_X;
    syscall_sysenter_event.callback = syscall_sysenter_cb;

    memset(&single_event, 0, sizeof(vmi_event_t));
    single_event.type = VMI_EVENT_SINGLESTEP;
    single_event.callback = single_step_cb;
    single_event.ss_event.enable = 1;
    SET_VCPU_SINGLESTEP(single_event.ss_event, 0);

    if(vmi_register_event(vmi, &syscall_sysenter_event) == VMI_FAILURE) {
        fprintf(stderr, "Could not install sysenter syscall handler.\n");
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
    vmi_destroy(vmi);

    return 0;

}
