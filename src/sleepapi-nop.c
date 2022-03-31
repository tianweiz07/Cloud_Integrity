#include "vmi.h"

/**
 * We are tracking two events: sys_nanosleep and sys_clock_nanosleep
 * For EPT, we need two vmi_event_t structure
 * For INT3, we only need one
 */
vmi_event_t nanosleep_enter_event;
vmi_event_t clock_nanosleep_enter_event;

vmi_event_t nanosleep_step_event;
vmi_event_t clock_nanosleep_step_event;

addr_t virt_sys_nanosleep;
addr_t phys_sys_nanosleep;

addr_t virt_sys_clock_nanosleep;
addr_t phys_sys_clock_nanosleep;

#ifndef MEM_EVENT
uint32_t sys_nanosleep_orig_data;
uint32_t sys_clock_nanosleep_orig_data;
#endif

char **list;
int num_proc;

/**
 * Check if the process name matches the one we ask for.
 */
int find_name(vmi_instance_t vmi, vmi_pid_t pid) {
    addr_t list_head = 0, next_list_entry = 0, current_process = 0;
    vmi_pid_t pid1 = 0;

    addr_t init_task_addr;
    vmi_translate_ksym2v(vmi, "init_task", &init_task_addr);

    list_head = init_task_addr + tasks_offset;
    next_list_entry = list_head;

    do {
        current_process = next_list_entry - tasks_offset;
        vmi_read_32_va(vmi, current_process + pid_offset, 0, (uint32_t*)&pid1);
        if (pid1 == pid) {
            int i;
            for (i=0; i<num_proc; i++) {
                if(!strcmp(list[i], vmi_read_str_va(vmi, current_process + name_offset, 0)))
                    return 1;
            }
            break;
        }
        status_t status = vmi_read_addr_va(vmi, next_list_entry, 0, &next_list_entry);
        if (status == VMI_FAILURE) {
            printf("Failed to read next pointer in loop at %"PRIx64"\n", next_list_entry);
            break;
        }
    } while(next_list_entry != list_head);
    return 0;
}


event_response_t clock_nanosleep_step_cb(vmi_instance_t vmi, vmi_event_t *event) {
    /**
     * enable the syscall entry interrupt
     */
#ifdef MEM_EVENT
    vmi_register_event(vmi, &clock_nanosleep_enter_event);
#else
    clock_nanosleep_enter_event.interrupt_event.reinject = 1;
    if (set_breakpoint(vmi, virt_sys_clock_nanosleep, 0) < 0) {
        printf("Could not set break points\n");
        exit(1);
    }
#endif

    /** 
     * disable the single event
     */
    vmi_clear_event(vmi, &clock_nanosleep_step_event, NULL);
    return 0;
}

event_response_t nanosleep_step_cb(vmi_instance_t vmi, vmi_event_t *event) {
    /**
     * enable the syscall entry interrupt
     */
#ifdef MEM_EVENT
    vmi_register_event(vmi, &nanosleep_enter_event);
#else
    nanosleep_enter_event.interrupt_event.reinject = 1;
    if (set_breakpoint(vmi, virt_sys_nanosleep, 0) < 0) {
        printf("Could not set break points\n");
        exit(1);
    }
#endif

    /** 
     * disable the single event
     */
    vmi_clear_event(vmi, &nanosleep_step_event, NULL);
    return 0;
}

event_response_t clock_nanosleep_enter_cb(vmi_instance_t vmi, vmi_event_t *event){
    if (event->mem_event.gla == virt_sys_clock_nanosleep) {
        reg_t rax, cr3, rsp;
        vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);
        vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);
        vmi_get_vcpureg(vmi, &rsp, RSP, event->vcpu_id);

        vmi_pid_t pid = -1;
        vmi_dtb_to_pid(vmi, cr3, &pid);
        /**
         * the calling process has the given process name, so nop this sleep call.
         */

        if (find_name(vmi, pid)) {

            /**
             * increase the stack pointer to pop out the RIP
             */
            vmi_set_vcpureg(vmi, rsp+8, RSP, event->vcpu_id);

            /**
             * set the return value
             */
            vmi_set_vcpureg(vmi, 0, RAX, event->vcpu_id);
            uint64_t rip;

            /**
             * move the return address from the stack to the RIP
             */
            vmi_read_64_va(vmi, rsp, pid, &rip);
            vmi_set_vcpureg(vmi, rip, RIP, event->vcpu_id);
        }
    }

    /**
     * disable the syscall entry interrupt
     */
    vmi_clear_event(vmi, event, NULL);

    /**
     * set the single event to execute one instruction
     */
    vmi_register_event(vmi, &clock_nanosleep_step_event);

    return 0;
}

event_response_t nanosleep_enter_cb(vmi_instance_t vmi, vmi_event_t *event){
#ifdef MEM_EVENT
    if (event->mem_event.gla == virt_sys_nanosleep) {
        reg_t rax, cr3, rsp;
        vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);
        vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);
        vmi_get_vcpureg(vmi, &rsp, RSP, event->vcpu_id);

        vmi_pid_t pid = -1;
        vmi_dtb_to_pid(vmi, cr3, &pid);

        if (find_name(vmi, pid)) {
            vmi_set_vcpureg(vmi, rsp+8, RSP, event->vcpu_id);
            vmi_set_vcpureg(vmi, 0, RAX, event->vcpu_id);
            uint64_t rip;
            vmi_read_64_va(vmi, rsp, pid, &rip);
            vmi_set_vcpureg(vmi, rip, RIP, event->vcpu_id);
        }
    }

    vmi_clear_event(vmi, event, NULL);
    vmi_register_event(vmi, &nanosleep_step_event);
#else
    if (event->interrupt_event.gla == virt_sys_nanosleep) {
        reg_t rax, cr3, rsp;
        vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);
        vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);
        vmi_get_vcpureg(vmi, &rsp, RSP, event->vcpu_id);

        vmi_pid_t pid = vmi_dtb_to_pid(vmi, cr3);

        if (find_name(vmi, pid)) {
            vmi_set_vcpureg(vmi, rsp+8, RSP, event->vcpu_id);
            vmi_set_vcpureg(vmi, 0, RAX, event->vcpu_id);
            uint64_t rip;
            vmi_read_64_va(vmi, rsp, pid, &rip);
            vmi_set_vcpureg(vmi, rip, RIP, event->vcpu_id);
        }

        event->interrupt_event.reinject = 0;
        if (VMI_FAILURE == vmi_write_32_va(vmi, virt_sys_nanosleep, 0, &sys_nanosleep_orig_data)) {
            printf("failed to write memory.\n");
            exit(1);
        }
        vmi_register_event(vmi, &nanosleep_step_event);
    } else if (event->interrupt_event.gla == virt_sys_clock_nanosleep) {
        reg_t rax, cr3, rsp;
        vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);
        vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);
        vmi_get_vcpureg(vmi, &rsp, RSP, event->vcpu_id);

        vmi_pid_t pid = vmi_dtb_to_pid(vmi, cr3);

        if (find_name(vmi, pid)) {
            vmi_set_vcpureg(vmi, rsp+8, RSP, event->vcpu_id);
            vmi_set_vcpureg(vmi, 0, RAX, event->vcpu_id);
            uint64_t rip;
            vmi_read_64_va(vmi, rsp, pid, &rip);
            vmi_set_vcpureg(vmi, rip, RIP, event->vcpu_id);
        }

        event->interrupt_event.reinject = 0;
        if (VMI_FAILURE == vmi_write_32_va(vmi, virt_sys_clock_nanosleep, 0, &sys_clock_nanosleep_orig_data)) {
            printf("failed to write memory.\n");
            exit(1);
        }
        vmi_register_event(vmi, &clock_nanosleep_step_event);
    }
#endif

    return 0;
}

int introspect_sleepapi_nop (char *name) {

    struct sigaction act;
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    vmi_instance_t vmi = NULL;
    vmi_init_data_t *init_data = NULL;
    uint8_t init = VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, config_type = VMI_CONFIG_GLOBAL_FILE_ENTRY;
    void *input = NULL, *config = NULL;
    vmi_init_error_t *error = NULL;

    vmi_mode_t mode;
    if (VMI_FAILURE == vmi_get_access_mode(NULL, name, VMI_INIT_DOMAINNAME| VMI_INIT_EVENTS, init_data, &mode)) {
        printf("Failed to find a supported hypervisor with LibVMI\n");
        return 1;
    }

    /* initialize the libvmi library */
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

    /**
     * get the list of process names that to NOP their sleep API, from the file blacklist.txt.
     */
    num_proc = 0;
    char _line[256];
    char _name[256];
    char _val[256];

    FILE *_file = fopen("blacklist.txt", "r");
    while(fgets(_line, sizeof(_line), _file) != NULL){
        sscanf(_line, "%s\t%s", _name, _val);
        list = realloc(list, sizeof(char*) * ++num_proc);
        list[num_proc-1] = (char*) malloc(256);
        strcpy(list[num_proc-1], _name);
    }
    fclose(_file);


    /**
     * get the task struct offsets from the libvmi confi file. 
     */
    vmi_get_offset(vmi, "linux_tasks", &tasks_offset);
    vmi_get_offset(vmi, "linux_name", &name_offset);
    vmi_get_offset(vmi, "linux_pid", &pid_offset);

    /**
     * get the address of two syscalls for sleep: sys_nanosleep and sys_clock_nanosleep
     */
    vmi_translate_ksym2v(vmi, "sys_nanosleep", &virt_sys_nanosleep);
    vmi_translate_kv2p(vmi, virt_sys_nanosleep, &phys_sys_nanosleep);
    vmi_translate_ksym2v(vmi, "sys_clock_nanosleep", &virt_sys_clock_nanosleep);
    vmi_translate_kv2p(vmi, virt_sys_clock_nanosleep, &phys_sys_clock_nanosleep);

    memset(&nanosleep_enter_event, 0, sizeof(vmi_event_t));
    memset(&clock_nanosleep_enter_event, 0, sizeof(vmi_event_t));

#ifdef MEM_EVENT
    /**
     * iniialize the memory event for EPT violation.
     */
    uint64_t gfn = phys_sys_nanosleep >> 12;
    SETUP_MEM_EVENT(&nanosleep_enter_event, gfn, VMI_MEMACCESS_X, &nanosleep_enter_cb, false);

    gfn = phys_sys_nanosleep >> 12;
    SETUP_MEM_EVENT(&clock_nanosleep_enter_event, gfn, VMI_MEMACCESS_X, &clock_nanosleep_enter_cb, false);

#else
    /**
     * iniialize the interrupt event for INT3.
     */
    nanosleep_enter_event.type = VMI_EVENT_INTERRUPT;
    nanosleep_enter_event.interrupt_event.intr = INT3;
    nanosleep_enter_event.callback = nanosleep_enter_cb;
#endif

    /**
     * iniialize the single step event.
     */
    memset(&nanosleep_step_event, 0, sizeof(vmi_event_t));
    nanosleep_step_event.type = VMI_EVENT_SINGLESTEP;
    nanosleep_step_event.callback = nanosleep_step_cb;
    nanosleep_step_event.ss_event.enable = 1;
    SET_VCPU_SINGLESTEP(nanosleep_step_event.ss_event, 0);

    memset(&clock_nanosleep_step_event, 0, sizeof(vmi_event_t));
    clock_nanosleep_step_event.type = VMI_EVENT_SINGLESTEP;
    clock_nanosleep_step_event.callback = clock_nanosleep_step_cb;
    clock_nanosleep_step_event.ss_event.enable = 1;
    SET_VCPU_SINGLESTEP(clock_nanosleep_step_event.ss_event, 0);

    /**
     * register the event.
     */
#ifdef MEM_EVENT
    if(vmi_register_event(vmi, &clock_nanosleep_enter_event) == VMI_FAILURE) {
        printf("Could not install register_chrdev handler.\n");
        goto exit;
    }
#endif

    if(vmi_register_event(vmi, &nanosleep_enter_event) == VMI_FAILURE) {
        printf("Could not install mod_sysfs_setup handler.\n");
        goto exit;
    }

#ifndef MEM_EVENT
    /**
     * store the original data for syscall entry function
     */
    if (VMI_FAILURE == vmi_read_32_va(vmi, virt_sys_nanosleep, 0, &sys_nanosleep_orig_data)) {
        printf("failed to read the original data.\n");
        vmi_destroy(vmi);
        return -1;
    }

    if (VMI_FAILURE == vmi_read_32_va(vmi, virt_sys_clock_nanosleep, 0, &sys_clock_nanosleep_orig_data)) {
        printf("failed to read the original data.\n");
        vmi_destroy(vmi);
        return -1;
    }

    /**
     * insert breakpoint into the syscall entry function
     */
    if (set_breakpoint(vmi, virt_sys_nanosleep, 0) < 0) {
        printf("Could not set break points\n");
        goto exit;
    }

    if (set_breakpoint(vmi, virt_sys_clock_nanosleep, 0) < 0) {
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
    if (VMI_FAILURE == vmi_write_32_va(vmi, virt_sys_nanosleep, 0, &sys_nanosleep_orig_data)) {
        printf("failed to write back the original data.\n");
    }

    if (VMI_FAILURE == vmi_write_32_va(vmi, virt_sys_clock_nanosleep, 0, &sys_clock_nanosleep_orig_data)) {
        printf("failed to write back the original data.\n");
    }

#endif

    vmi_destroy(vmi);
    return 0;
}
