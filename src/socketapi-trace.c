#include "vmi.h"

vmi_event_t accept_enter_event;
vmi_event_t accept_step_event;

addr_t virt_sys_accept;
addr_t phys_sys_accept;

addr_t virt_leave_sys_accept = 0;
addr_t phys_leave_sys_accept = 0;

addr_t virt_sys_connect;
addr_t phys_sys_connect;

#ifdef MEM_EVENT
/**
 * This event is for mem event
 * INT does not need to specify new events
 */
vmi_event_t accept_leave_event;
#else
uint32_t sys_accept_orig_data;
uint32_t sys_connect_orig_data;
uint32_t leave_sys_accept_orig_data;
#endif

addr_t sockaddr[32768];

int socket_event_type = 0;

event_response_t socket_step_cb(vmi_instance_t vmi, vmi_event_t *event) {
    /**
     * enable the syscall entry interrupt
     */
#ifdef MEM_EVENT
    if (socket_event_type == 1)
        vmi_register_event(vmi, &accept_enter_event);
    else if (socket_event_type == 3)
        vmi_register_event(vmi, &accept_leave_event);
#else
    accept_enter_event.interrupt_event.reinject = 1;
    if (socket_event_type == 1) {
        if (set_breakpoint(vmi, virt_sys_accept, 0) < 0) {
            printf("Could not set break points\n");
            exit(1);
        }
    } else if (socket_event_type == 2) {
        if (set_breakpoint(vmi, virt_sys_connect, 0) < 0) {
            printf("Could not set break points\n");
            exit(1);
        }
    } else if (socket_event_type == 3) {
        if (set_breakpoint(vmi, virt_leave_sys_accept, 0) < 0) {
            printf("Could not set break points\n");
            exit(1);
        }
    }
#endif

    /** 
     * disable the single event
     */
    vmi_clear_event(vmi, &accept_step_event, NULL);
    return 0;
}

event_response_t socket_enter_cb(vmi_instance_t vmi, vmi_event_t *event){
    addr_t event_addr;
#ifdef MEM_EVENT
    event_addr = event->mem_event.gla;
#else
    event_addr = event->interrupt_event.gla;
#endif

    /**
     * Case 1: entering the sys_accept syscall.
     */
    if (event_addr == virt_sys_accept) {
        reg_t cr3, rsi;
        vmi_get_vcpureg(vmi, &rsi, RSI, event->vcpu_id);
        vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);

        vmi_pid_t pid = vmi_dtb_to_pid(vmi, cr3);
        sockaddr[(int)pid] = rsi;

        /**
         * First time, the leave_sys_accept has not been set yet.
         */
        if (virt_leave_sys_accept == 0) {
            reg_t rbp;
            vmi_get_vcpureg(vmi, &rbp, RSP, event->vcpu_id);
            uint64_t rip;
            vmi_read_64_va(vmi, rbp, pid, &rip);

            virt_leave_sys_accept = rip;
            phys_leave_sys_accept = vmi_translate_kv2p(vmi, virt_leave_sys_accept);

            /**
             * Set the event notification when sys_accept finishes.
             */
#ifdef MEM_EVENT
            /**
             * initialize and register the event.
             */
            memset(&accept_leave_event, 0, sizeof(vmi_event_t));
            
            accept_leave_event.type = VMI_EVENT_MEMORY;
            accept_leave_event.mem_event.physical_address = phys_leave_sys_accept;
            accept_leave_event.mem_event.npages = 1;
            accept_leave_event.mem_event.granularity = VMI_MEMEVENT_PAGE;
            accept_leave_event.mem_event.in_access = VMI_MEMACCESS_X;
            accept_leave_event.callback = socket_enter_cb;

            if(vmi_register_event(vmi, &accept_leave_event) == VMI_FAILURE) {
                printf("Could not install socket handler.\n");
                return -1;
            }   
#else
            if (VMI_FAILURE == vmi_read_32_va(vmi, virt_leave_sys_accept, 0, &leave_sys_accept_orig_data)) {
                printf("failed to read the original data.\n");
                return -1;
            }

            /**
             * insert breakpoint into the syscall entry function
             */
            if (set_breakpoint(vmi, virt_leave_sys_accept, 0) < 0) {
                printf("Could not set break points\n");
                return -1;
            }
#endif       
        }
    }

    /**
     * Case 2: entering the sys_connect syscall.
     */
    else if (event_addr == virt_sys_connect) {
        reg_t cr3, rsi, rdx;
        vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);
        vmi_get_vcpureg(vmi, &rsi, RSI, event->vcpu_id);
        vmi_get_vcpureg(vmi, &rdx, RDX, event->vcpu_id);
        vmi_pid_t pid = vmi_dtb_to_pid(vmi, cr3);

        /**
         * If this is called by the socket api, then the length of the parameter should be 16.
         */
        if ((int)rdx == 16) {
            uint8_t ip_addr[4];
            uint8_t port[2];
            vmi_read_8_va(vmi, rsi+2, pid, &port[0]);
            vmi_read_8_va(vmi, rsi+3, pid, &port[1]);
            vmi_read_8_va(vmi, rsi+4, pid, &ip_addr[0]);
            vmi_read_8_va(vmi, rsi+5, pid, &ip_addr[1]);
            vmi_read_8_va(vmi, rsi+6, pid, &ip_addr[2]);
            vmi_read_8_va(vmi, rsi+7, pid, &ip_addr[3]);
            printf("Connect to %d:%d:%d:%d:%d\n", ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3], port[0]*256+port[1]);
        }
    }

    /**
     * Case 3: leaving the sys_accept syscall.
     */
    else if (event_addr == virt_leave_sys_accept) {
        reg_t cr3, rax;
        vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);
        vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);
        vmi_pid_t pid = vmi_dtb_to_pid(vmi, cr3);

        /**
         * must check the pid is valid, and the return address is true.
         */
        if (sockaddr[(int)pid] > 0 && ((int)rax > 0)) {
            uint8_t ip_addr[4];
            uint8_t port[2];
            vmi_read_8_va(vmi, sockaddr[(int)pid]+2, pid, &port[0]);
            vmi_read_8_va(vmi, sockaddr[(int)pid]+3, pid, &port[1]);
            vmi_read_8_va(vmi, sockaddr[(int)pid]+4, pid, &ip_addr[0]);
            vmi_read_8_va(vmi, sockaddr[(int)pid]+5, pid, &ip_addr[1]);
            vmi_read_8_va(vmi, sockaddr[(int)pid]+6, pid, &ip_addr[2]);
            vmi_read_8_va(vmi, sockaddr[(int)pid]+7, pid, &ip_addr[3]);
            printf("Accept connection from %d:%d:%d:%d:%d\n", ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3], port[0]*256+port[1]);
            sockaddr[(int)pid] = 0;
        }
    }

    /**
     * disable the syscall entry interrupt
     */
#ifdef MEM_EVENT
    vmi_clear_event(vmi, event, NULL);
    if ((event_addr >> 12) == (virt_sys_accept >> 12))
        socket_event_type = 1;
    else if ((event_addr >> 12) == (virt_leave_sys_accept >> 12))
        socket_event_type = 3;
    else {
        printf("Error in disabling event\n");
        return -1;
    }
#else
    event->interrupt_event.reinject = 0;
    if (event_addr == virt_sys_accept) {
        if (VMI_FAILURE == vmi_write_32_va(vmi, virt_sys_accept, 0, &sys_accept_orig_data)) {
            printf("failed to write memory.\n");
            exit(1);
        }
        socket_event_type = 1;
    } else if (event_addr == virt_sys_connect) {
        if (VMI_FAILURE == vmi_write_32_va(vmi, virt_sys_connect, 0, &sys_connect_orig_data)) {
            printf("failed to write memory.\n");
            exit(1);
        }
        socket_event_type = 2;
    } else if (event_addr == virt_leave_sys_accept) {
        if (VMI_FAILURE == vmi_write_32_va(vmi, virt_leave_sys_accept, 0, &leave_sys_accept_orig_data)) {
            printf("failed to write memory.\n");
            exit(1);
        }
        socket_event_type = 3;
    } else {
        printf("Error in disabling event\n");
        return -1;
    }
#endif

    /**
     * set the single event to execute one instruction
     */
    vmi_register_event(vmi, &accept_step_event);

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
    virt_sys_accept = vmi_translate_ksym2v(vmi, "sys_accept");
    phys_sys_accept = vmi_translate_kv2p(vmi, virt_sys_accept);

    virt_sys_connect = vmi_translate_ksym2v(vmi, "sys_connect");
    phys_sys_connect = vmi_translate_kv2p(vmi, virt_sys_connect);

    memset(&accept_enter_event, 0, sizeof(vmi_event_t));

#ifdef MEM_EVENT
    /**
     * iniialize the memory event for EPT violation.
     * It happens that sys_accept and sys_connect are in the same page
     * So just need one memory event, and error will be reported if specified two.
     * If they are in different pages, then we need two separate memory events
     */
    accept_enter_event.type = VMI_EVENT_MEMORY;
    accept_enter_event.mem_event.physical_address = phys_sys_accept;
    accept_enter_event.mem_event.npages = 1;
    accept_enter_event.mem_event.granularity = VMI_MEMEVENT_PAGE;
    accept_enter_event.mem_event.in_access = VMI_MEMACCESS_X;
    accept_enter_event.callback = socket_enter_cb;
#else
    /**
     * iniialize the interrupt event for INT3.
     */
    accept_enter_event.type = VMI_EVENT_INTERRUPT;
    accept_enter_event.interrupt_event.intr = INT3;
    accept_enter_event.callback = socket_enter_cb;
#endif

    /**
     * iniialize the single step event.
     */
    memset(&accept_step_event, 0, sizeof(vmi_event_t));
    accept_step_event.type = VMI_EVENT_SINGLESTEP;
    accept_step_event.callback = socket_step_cb;
    accept_step_event.ss_event.enable = 1;
    SET_VCPU_SINGLESTEP(accept_step_event.ss_event, 0);

    /**
     * register the event.
     */
    if(vmi_register_event(vmi, &accept_enter_event) == VMI_FAILURE) {
        printf("Could not install socket handler.\n");
        goto exit;
    }

#ifndef MEM_EVENT
    /**
     * store the original data for syscall entry function
     */
    if (VMI_FAILURE == vmi_read_32_va(vmi, virt_sys_accept, 0, &sys_accept_orig_data)) {
        printf("failed to read the original data.\n");
        vmi_destroy(vmi);
        return -1;
    }

    if (VMI_FAILURE == vmi_read_32_va(vmi, virt_sys_connect, 0, &sys_connect_orig_data)) {
        printf("failed to read the original data.\n");
        vmi_destroy(vmi);
        return -1;
    }

    /**
     * insert breakpoint into the syscall entry function
     */
    if (set_breakpoint(vmi, virt_sys_accept, 0) < 0) {
        printf("Could not set break points\n");
        goto exit;
    }
    if (set_breakpoint(vmi, virt_sys_connect, 0) < 0) {
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
    if (VMI_FAILURE == vmi_write_32_va(vmi, virt_sys_accept, 0, &sys_accept_orig_data)) {
        printf("failed to write back the original data.\n");
    }
    if (VMI_FAILURE == vmi_write_32_va(vmi, virt_sys_connect, 0, &sys_connect_orig_data)) {
        printf("failed to write back the original data.\n");
    }
    if (virt_leave_sys_accept > 0) {
        if (VMI_FAILURE == vmi_write_32_va(vmi, virt_leave_sys_accept, 0, &leave_sys_accept_orig_data)) {
            printf("failed to write back the original data.\n");
        }
    }
#endif

    vmi_destroy(vmi);
    return 0;
}
