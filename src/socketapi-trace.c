#include "vmi.h"

vmi_event_t socket_enter_event;
vmi_event_t socket_step_event;

addr_t virt_sys_socket;
addr_t phys_sys_socket;

#ifndef MEM_EVENT
uint32_t sys_socket_orig_data;
#endif

event_response_t socket_step_cb(vmi_instance_t vmi, vmi_event_t *event) {
    /**
     * enable the syscall entry interrupt
     */
#ifdef MEM_EVENT
    vmi_register_event(vmi, &socket_enter_event);
#else
    socket_enter_event.interrupt_event.reinject = 1;
    if (set_breakpoint(vmi, virt_sys_socket, 0) < 0) {
        printf("Could not set break points\n");
        exit(1);
    }
#endif

    /** 
     * disable the single event
     */
    vmi_clear_event(vmi, &socket_step_event, NULL);
    return 0;
}


event_response_t socket_enter_cb(vmi_instance_t vmi, vmi_event_t *event){
#ifdef MEM_EVENT
    if (event->mem_event.gla == virt_sys_socket) {
#else
    if (event->interrupt_event.gla == virt_sys_socket) {
#endif
        reg_t rdi, rax, cr3;
        vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);
        vmi_get_vcpureg(vmi, &rdi, RDI, event->vcpu_id);
        vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);

        vmi_pid_t pid = vmi_dtb_to_pid(vmi, cr3);

        printf("Process[%d] establish a network socket\n", pid);
    }

    /**
     * disable the syscall entry interrupt
     */
#ifdef MEM_EVENT
    vmi_clear_event(vmi, event, NULL);
#else
    event->interrupt_event.reinject = 0;
    if (VMI_FAILURE == vmi_write_32_va(vmi, virt_sys_socket, 0, &sys_socket_orig_data)) {
        printf("failed to write memory.\n");
        exit(1);
    }
#endif

    /**
     * set the single event to execute one instruction
     */
    vmi_register_event(vmi, &socket_step_event);
    return 0;
}

int introspect_socketapi_trace (char *name) {

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
        vmi_destroy(vmi);
        return 1;
    }

    /**
     * get the address of sys_socket from the sysmap
     */
    virt_sys_socket = vmi_translate_ksym2v(vmi, "sys_socket");
    phys_sys_socket = vmi_translate_kv2p(vmi, virt_sys_socket);

    memset(&socket_enter_event, 0, sizeof(vmi_event_t));

#ifdef MEM_EVENT
    /**
     * iniialize the memory event for EPT violation.
     */
    socket_enter_event.type = VMI_EVENT_MEMORY;
    socket_enter_event.mem_event.physical_address = phys_sys_socket;
    socket_enter_event.mem_event.npages = 1;
    socket_enter_event.mem_event.granularity = VMI_MEMEVENT_PAGE;
    socket_enter_event.mem_event.in_access = VMI_MEMACCESS_X;
    socket_enter_event.callback = socket_enter_cb;
#else
    /**
     * iniialize the interrupt event for INT3.
     */
    socket_enter_event.type = VMI_EVENT_INTERRUPT;
    socket_enter_event.interrupt_event.intr = INT3;
    socket_enter_event.callback = socket_enter_cb;
#endif

    /**
     * iniialize the single step event.
     */
    memset(&socket_step_event, 0, sizeof(vmi_event_t));
    socket_step_event.type = VMI_EVENT_SINGLESTEP;
    socket_step_event.callback = socket_step_cb;
    socket_step_event.ss_event.enable = 1;
    SET_VCPU_SINGLESTEP(socket_step_event.ss_event, 0);

    /**
     * register the event.
     */
    if(vmi_register_event(vmi, &socket_enter_event) == VMI_FAILURE) {
        printf("Could not install socket handler.\n");
        goto exit;
    }

#ifndef MEM_EVENT
    /**
     * store the original data for syscall entry function
     */
    if (VMI_FAILURE == vmi_read_32_va(vmi, virt_sys_socket, 0, &sys_socket_orig_data)) {
        printf("failed to read the original data.\n");
        vmi_destroy(vmi);
        return -1;
    }

    /**
     * insert breakpoint into the syscall entry function
     */
    if (set_breakpoint(vmi, virt_sys_socket, 0) < 0) {
        printf("Could not set break points\n");
        goto exit;
    }
#endif

    while(!interrupted){
        if (vmi_events_listen(vmi, 1000) != VMI_SUCCESS) {
            printf("Error waiting for events, quitting...\n");
            interrupted = -1;
        }
    }

exit:

#ifndef MEM_EVENT
    /**
     * write back the original data
     */
    if (VMI_FAILURE == vmi_write_32_va(vmi, virt_sys_socket, 0, &sys_socket_orig_data)) {
        printf("failed to write back the original data.\n");
    }
#endif

    vmi_destroy(vmi);
    return 0;
}
