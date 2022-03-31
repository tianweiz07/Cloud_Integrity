#include "vmi.h"

vmi_event_t syscall_enter_event;
vmi_event_t syscall_step_event;

reg_t virt_lstar;
addr_t phys_lstar;

int num_sys = 0;
char **sys_index = NULL;

#ifndef MEM_EVENT
uint32_t syscall_orig_data;
#endif

event_response_t syscall_step_cb(vmi_instance_t vmi, vmi_event_t *event) {
    /**
     * enable the syscall entry interrupt
     */
#ifdef MEM_EVENT
    vmi_register_event(vmi, &syscall_enter_event);
#else
    syscall_enter_event.interrupt_event.reinject = 1;
    if (set_breakpoint(vmi, virt_lstar, 0) < 0) {
        printf("Could not set break points\n");
        exit(1);
    }
#endif

    /** 
     * disable the single event
     */
    vmi_clear_event(vmi, &syscall_step_event, NULL);
    return 0;
}


event_response_t syscall_enter_cb(vmi_instance_t vmi, vmi_event_t *event){
#ifdef MEM_EVENT
    if (event->mem_event.gla == virt_lstar) {
#else
    if (event->interrupt_event.gla == virt_lstar) {
#endif
        reg_t rdi, rax, cr3;
        vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);
        vmi_get_vcpureg(vmi, &rdi, RDI, event->vcpu_id);
        vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);

        
        vmi_pid_t pid = -1;
        vmi_dtb_to_pid(vmi, cr3, &pid);

        uint16_t _index = (uint16_t)rax;
        if (_index >= num_sys) {
            printf("Process[%d]: unknown syscall id: %d\n", pid, _index);

        } else if (_index == 90 ) {
            char *argname = NULL;
            argname = vmi_read_str_va(vmi, rdi, pid);
            printf("Process[%d]: Syscall %s happend, 1st argument=%s\n", pid, sys_index[_index], argname);
        } else {
            printf("Process[%d]: Syscall %s happened, 1st argument=%u\n", pid, sys_index[_index], (unsigned int)rdi);
        }

    }

    /**
     * disable the syscall entry interrupt
     */
#ifdef MEM_EVENT
    vmi_clear_event(vmi, event, NULL);
#else
    event->interrupt_event.reinject = 0;
    if (VMI_FAILURE == vmi_write_32_va(vmi, virt_lstar, 0, &syscall_orig_data)) {
        printf("failed to write memory.\n");
        exit(1);
    }
#endif

    /**
     * set the single event to execute one instruction
     */
    vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);
    vmi_register_event(vmi, &syscall_step_event);
    return VMI_EVENT_RESPONSE_NONE;
}

int introspect_syscall_trace (char *name) {

    struct sigaction act;
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    char _line[256];
    char _name[256];
    int _index[256];

    FILE *_file = fopen("data/syscall_index.linux", "r");
    if (_file == NULL)
        printf("Failed to read syscall file\n");

    while(fgets(_line, sizeof(_line), _file) != NULL){
        sscanf(_line, "%d\t%s", _index, _name);
        sys_index = realloc(sys_index, sizeof(char*) * ++num_sys);
        sys_index[num_sys-1] = (char*) malloc(256);
        strcpy(sys_index[num_sys-1], _name);
    }
    fclose(_file);

    vmi_instance_t vmi = NULL;
    vmi_init_data_t *init_data = NULL;
    uint8_t init = VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, config_type = VMI_CONFIG_GLOBAL_FILE_ENTRY;
    void *input = NULL, *config = NULL;
    vmi_init_error_t *error = NULL;
    vmi_mode_t mode;
    
    /* initialize the libvmi library */
    if (VMI_FAILURE == vmi_get_access_mode(NULL, name, VMI_INIT_DOMAINNAME| VMI_INIT_EVENTS, init_data, &mode)) {
        printf("Failed to find a supported hypervisor with LibVMI\n");
        return 1;
    }

    if (VMI_FAILURE == vmi_init(&vmi, mode, name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, init_data, NULL)) {
        printf("Failed to init LibVMI library.\n");
        return 1;
    }

    if ( VMI_PM_UNKNOWN == vmi_init_paging(vmi, 0) ) {
        printf("Failed to init determine paging.\n");
        vmi_destroy(vmi);
        return 1;
    }

    if ( VMI_OS_UNKNOWN == vmi_init_os(vmi, VMI_CONFIG_GLOBAL_FILE_ENTRY, config, error) ) {
        printf("Failed to init os.\n");
        vmi_destroy(vmi);
        return 1;
    }


    printf("LibVMI init succeeded!\n");

    memset(&syscall_enter_event, 0, sizeof(vmi_event_t));

#ifdef MEM_EVENT
    if (VMI_FAILURE ==  vmi_pause_vm(vmi)) {
        fprintf(stderr, "Failed to pause vm\n");
        return 1;
    }

    if (VMI_FAILURE == vmi_get_vcpureg(vmi, &virt_lstar, MSR_LSTAR, 0)) {
        fprintf(stderr, "Failed to get current RIP\n");
        return 1;
    }

    uint64_t cr3;
    if (VMI_FAILURE == vmi_get_vcpureg(vmi, &cr3, CR3, 0)) {
        fprintf(stderr, "Failed to get current CR3\n");
        return 1;
    }
    uint64_t dtb = cr3 & ~(0xfff);

    uint64_t paddr;
    if (VMI_FAILURE == vmi_pagetable_lookup(vmi, dtb, virt_lstar, &paddr)) {
        fprintf(stderr, "Failed to find current paddr\n");
        return 1;
    }

    uint64_t gfn = paddr >> 12;

    SETUP_MEM_EVENT(&syscall_enter_event, gfn, VMI_MEMACCESS_X, syscall_enter_cb, false);


    printf("Setting X memory event at LSTAR 0x%"PRIx64", GPA 0x%"PRIx64", GFN 0x%"PRIx64"\n",
           virt_lstar, paddr, gfn);

    if (VMI_FAILURE == vmi_register_event(vmi, &syscall_enter_event)) {
        fprintf(stderr, "Failed to register mem event\n");
        return 1;
    }

    // resuming
    if (VMI_FAILURE == vmi_resume_vm(vmi)) {
        fprintf(stderr, "Failed to resume vm\n");
        return 1;
    }

#else
    /**
     * iniialize the interrupt event for INT3.
     */
    syscall_enter_event.type = VMI_EVENT_INTERRUPT;
    syscall_enter_event.interrupt_event.intr = INT3;
    syscall_enter_event.callback = syscall_enter_cb;
#endif

    /**
     * iniialize the single step event.
     */
    memset(&syscall_step_event, 0, sizeof(vmi_event_t));
    SETUP_SINGLESTEP_EVENT(&syscall_step_event, 1, syscall_step_cb, 0);

#ifndef MEM_EVENT
    /**
     * store the original data for syscall entry function
     */
    if (VMI_FAILURE == vmi_read_32_va(vmi, virt_lstar, 0, &syscall_orig_data)) {
        printf("failed to read the original data.\n");
        vmi_destroy(vmi);
        return -1;
    }

    /**
     * insert breakpoint into the syscall entry function
     */
    if (set_breakpoint(vmi, virt_lstar, 0) < 0) {
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
    if (VMI_FAILURE == vmi_write_32_va(vmi, virt_lstar, 0, &syscall_orig_data)) {
        printf("failed to write back the original data.\n");
    }
#endif
    vmi_clear_event(vmi, &syscall_enter_event, NULL);
    vmi_destroy(vmi);
    return 0;
}
