#include "vmi.h"

/**
 * We are tracking two events: module initialization and device registeration
 * For EPT, we need two vmi_event_t structure
 * For INT3, we only need one
 */
vmi_event_t module_enter_event;
vmi_event_t module_step_event;

vmi_event_t chrdev_enter_event;
vmi_event_t chrdev_step_event;

addr_t virt_register_chrdev;
addr_t phys_register_chrdev;

addr_t virt_mod_sysfs_setup;
addr_t phys_mod_sysfs_setup;

#ifndef MEM_EVENT
uint32_t register_chrdev_orig_data;
uint32_t mod_sysfs_setup_orig_data;
#endif

event_response_t chrdev_step_cb(vmi_instance_t vmi, vmi_event_t *event) {
    /**
     * enable the syscall entry interrupt
     */
#ifdef MEM_EVENT
    vmi_register_event(vmi, &chrdev_enter_event);
#else
    chrdev_enter_event.interrupt_event.reinject = 1;
    if (set_breakpoint(vmi, virt_register_chrdev, 0) < 0) {
        printf("Could not set break points\n");
        exit(1);
    }
#endif

    /** 
     * disable the single event
     */
    vmi_clear_event(vmi, &chrdev_step_event, NULL);
    return 0;
}

event_response_t module_step_cb(vmi_instance_t vmi, vmi_event_t *event) {
    /**
     * enable the syscall entry interrupt
     */
#ifdef MEM_EVENT
    vmi_register_event(vmi, &module_enter_event);
#else
    module_enter_event.interrupt_event.reinject = 1;
    if (set_breakpoint(vmi, virt_mod_sysfs_setup, 0) < 0) {
        printf("Could not set break points\n");
        exit(1);
    }
#endif

    /** 
     * disable the single event
     */
    vmi_clear_event(vmi, &module_step_event, NULL);
    return 0;
}


event_response_t chrdev_enter_cb(vmi_instance_t vmi, vmi_event_t *event){
    /**
     * INT3 event will never reach this function
     */
    if (event->mem_event.gla == virt_register_chrdev) {
        reg_t rcx, cr3;
        vmi_get_vcpureg(vmi, &rcx, RCX, event->vcpu_id);
        vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);

        vmi_pid_t pid = vmi_dtb_to_pid(vmi, cr3);
        char *argname = NULL;
        argname = vmi_read_str_va(vmi, rcx, 0);
        printf("Process [%d] registers a Character Device: %s\n", pid, argname);
        free(argname);
    }

    /**
     * disable the syscall entry interrupt
     */
    vmi_clear_event(vmi, event, NULL);

    /**
     * set the single event to execute one instruction
     */
    vmi_register_event(vmi, &chrdev_step_event);
    return 0;
}


event_response_t module_enter_cb(vmi_instance_t vmi, vmi_event_t *event){
#ifdef MEM_EVENT
    if (event->mem_event.gla == virt_mod_sysfs_setup) {
        reg_t rdi, cr3;
        vmi_get_vcpureg(vmi, &rdi, RDI, event->vcpu_id);
        vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);

        vmi_pid_t pid = vmi_dtb_to_pid(vmi, cr3);
        char *argname = NULL;
        argname = vmi_read_str_va(vmi, (addr_t)rdi+24, 0);
        printf("Process [%d] inserts a kernel module: %s\n", pid, argname);
        free(argname);
    }

    /**
     * disable the syscall entry interrupt
     */
    vmi_clear_event(vmi, event, NULL);

    /**
     * set the single event to execute one instruction
     */
    vmi_register_event(vmi, &module_step_event);
#else
    if (event->interrupt_event.gla == virt_mod_sysfs_setup) {
        reg_t rdi, cr3;
        vmi_get_vcpureg(vmi, &rdi, RDI, event->vcpu_id);
        vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);

        vmi_pid_t pid = vmi_dtb_to_pid(vmi, cr3);
        char *argname = NULL;
        argname = vmi_read_str_va(vmi, (addr_t)rdi+24, 0);
        printf("Process [%d] inserts a kernel module: %s\n", pid, argname);
        free(argname);

        event->interrupt_event.reinject = 0;
        if (VMI_FAILURE == vmi_write_32_va(vmi, virt_mod_sysfs_setup, 0, &mod_sysfs_setup_orig_data)) {
            printf("failed to write memory.\n");
            exit(1);
        }
        vmi_register_event(vmi, &module_step_event);
    } else if (event->interrupt_event.gla == virt_register_chrdev) {
        reg_t rcx, cr3;
        vmi_get_vcpureg(vmi, &rcx, RCX, event->vcpu_id);
        vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);

        vmi_pid_t pid = vmi_dtb_to_pid(vmi, cr3);
        char *argname = NULL;
        argname = vmi_read_str_va(vmi, rcx, 0);
        printf("Process [%d] registers a Character Device: %s\n", pid, argname);
        free(argname);

        event->interrupt_event.reinject = 0;
        if (VMI_FAILURE == vmi_write_32_va(vmi, virt_register_chrdev, 0, &register_chrdev_orig_data)) {
            printf("failed to write memory.\n");
            exit(1);
        }
        vmi_register_event(vmi, &chrdev_step_event);
    }
        
#endif

    return 0;
}

int introspect_driverapi_trace (char *name) {

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
     * get the address of register_chrdev and mod_sysfs_setup from the sysmap
     * mod_sysfs_setup is the key function called by init_module
     * register_chrdev is the key function when registering char devices.
     */
    virt_register_chrdev = vmi_translate_ksym2v(vmi, "__register_chrdev");
    phys_register_chrdev = vmi_translate_kv2p(vmi, virt_register_chrdev);
    virt_mod_sysfs_setup = vmi_translate_ksym2v(vmi, "mod_sysfs_setup");
    phys_mod_sysfs_setup = vmi_translate_kv2p(vmi, virt_mod_sysfs_setup);

    memset(&chrdev_enter_event, 0, sizeof(vmi_event_t));
    memset(&module_enter_event, 0, sizeof(vmi_event_t));

#ifdef MEM_EVENT
    /**
     * iniialize the memory event for EPT violation.
     */
    chrdev_enter_event.type = VMI_EVENT_MEMORY;
    chrdev_enter_event.mem_event.physical_address = phys_register_chrdev;
    chrdev_enter_event.mem_event.npages = 1;
    chrdev_enter_event.mem_event.granularity = VMI_MEMEVENT_PAGE;
    chrdev_enter_event.mem_event.in_access = VMI_MEMACCESS_X;
    chrdev_enter_event.callback = chrdev_enter_cb;

    module_enter_event.type = VMI_EVENT_MEMORY;
    module_enter_event.mem_event.physical_address = phys_mod_sysfs_setup;
    module_enter_event.mem_event.npages = 1;
    module_enter_event.mem_event.granularity = VMI_MEMEVENT_PAGE;
    module_enter_event.mem_event.in_access = VMI_MEMACCESS_X;
    module_enter_event.callback = module_enter_cb;
#else
    /**
     * iniialize the interrupt event for INT3.
     */
    module_enter_event.type = VMI_EVENT_INTERRUPT;
    module_enter_event.interrupt_event.intr = INT3;
    module_enter_event.callback = module_enter_cb;
#endif

    /**
     * iniialize the single step event.
     */
    memset(&chrdev_step_event, 0, sizeof(vmi_event_t));
    chrdev_step_event.type = VMI_EVENT_SINGLESTEP;
    chrdev_step_event.callback = chrdev_step_cb;
    chrdev_step_event.ss_event.enable = 1;
    SET_VCPU_SINGLESTEP(chrdev_step_event.ss_event, 0);

    memset(&module_step_event, 0, sizeof(vmi_event_t));
    module_step_event.type = VMI_EVENT_SINGLESTEP;
    module_step_event.callback = module_step_cb;
    module_step_event.ss_event.enable = 1;
    SET_VCPU_SINGLESTEP(module_step_event.ss_event, 0);

    /**
     * register the event.
     */
#ifdef MEM_EVENT
    if(vmi_register_event(vmi, &chrdev_enter_event) == VMI_FAILURE) {
        printf("Could not install register_chrdev handler.\n");
        goto exit;
    }
#endif

    if(vmi_register_event(vmi, &module_enter_event) == VMI_FAILURE) {
        printf("Could not install mod_sysfs_setup handler.\n");
        goto exit;
    }

#ifndef MEM_EVENT
    /**
     * store the original data for syscall entry function
     */
    if (VMI_FAILURE == vmi_read_32_va(vmi, virt_register_chrdev, 0, &register_chrdev_orig_data)) {
        printf("failed to read the original data.\n");
        vmi_destroy(vmi);
        return -1;
    }

    if (VMI_FAILURE == vmi_read_32_va(vmi, virt_mod_sysfs_setup, 0, &mod_sysfs_setup_orig_data)) {
        printf("failed to read the original data.\n");
        vmi_destroy(vmi);
        return -1;
    }

    /**
     * insert breakpoint into the syscall entry function
     */
    if (set_breakpoint(vmi, virt_register_chrdev, 0) < 0) {
        printf("Could not set break points\n");
        goto exit;
    }

    if (set_breakpoint(vmi, virt_mod_sysfs_setup, 0) < 0) {
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
    if (VMI_FAILURE == vmi_write_32_va(vmi, virt_register_chrdev, 0, &register_chrdev_orig_data)) {
        printf("failed to write back the original data.\n");
    }

    if (VMI_FAILURE == vmi_write_32_va(vmi, virt_mod_sysfs_setup, 0, &mod_sysfs_setup_orig_data)) {
        printf("failed to write back the original data.\n");
    }

#endif

    vmi_destroy(vmi);
    return 0;
}
