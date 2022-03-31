#include "vmi.h"

vmi_event_t kill_enter_event;
vmi_event_t kill_step_event;

addr_t virt_schedule;

uint32_t schedule_orig_data;
uint32_t leave_kill_orig_data;

int kill_flag = -1;

reg_t rax_orig, rbx_orig, rcx_orig, rdx_orig, rbp_orig, rsi_orig, rsp_orig, rip_orig;

int KILL_PID;

void save_context(vmi_instance_t vmi, vmi_event_t *event) {

    /* Save the registers */
    vmi_get_vcpureg(vmi, &rax_orig, RAX, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rbx_orig, RBX, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rcx_orig, RCX, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rdx_orig, RDX, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rbp_orig, RBP, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rsi_orig, RSI, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rsp_orig, RSP, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rip_orig, RIP, event->vcpu_id);
}

void restore_context(vmi_instance_t vmi, vmi_event_t *event) {
    /* Restore the registers */
    vmi_set_vcpureg(vmi, rax_orig, RAX, event->vcpu_id);
    vmi_set_vcpureg(vmi, rbx_orig, RBX, event->vcpu_id);
    vmi_set_vcpureg(vmi, rcx_orig, RCX, event->vcpu_id);
    vmi_set_vcpureg(vmi, rdx_orig, RDX, event->vcpu_id);
    vmi_set_vcpureg(vmi, rbp_orig, RBP, event->vcpu_id);
    vmi_set_vcpureg(vmi, rsi_orig, RSI, event->vcpu_id);
    vmi_set_vcpureg(vmi, rsp_orig, RSP, event->vcpu_id);
}

event_response_t kill_step_cb(vmi_instance_t vmi, vmi_event_t *event) {

    if (kill_flag == 0) {

        save_context(vmi, event);

        /* Modify the registers of parameters */
        vmi_set_vcpureg(vmi, KILL_PID, RDI, event->vcpu_id);
        vmi_set_vcpureg(vmi, 9, RSI, event->vcpu_id);

        /* Modify the registers of stack */
        vmi_set_vcpureg(vmi, rsp_orig-8, RSP, event->vcpu_id);
        vmi_write_64_va(vmi, rsp_orig-8, 0, &rip_orig);

        addr_t sys_kill_addr;
        vmi_translate_ksym2v(vmi, "sys_kill", &sys_kill_addr);

        vmi_set_vcpureg(vmi, sys_kill_addr, RIP, event->vcpu_id);

        vmi_read_32_va(vmi, rip_orig, 0, &leave_kill_orig_data);
        set_breakpoint(vmi, rip_orig, 0);

    } else if (kill_flag == 1) {
        interrupted = -1;
    }

    vmi_clear_event(vmi, &kill_step_event, NULL);

    return 0;
}

event_response_t kill_enter_cb(vmi_instance_t vmi, vmi_event_t *event){
    event->interrupt_event.reinject = 0;

    if (event->interrupt_event.gla == virt_schedule) {
        kill_flag = 0;
        if (VMI_FAILURE == vmi_write_32_va(vmi, virt_schedule, 0, &schedule_orig_data)) {
            printf("failed to write memory.\n");
            exit(1);
        }
    } else if (event->interrupt_event.gla == rip_orig) {

        kill_flag = 1;        
        vmi_write_32_va(vmi, rip_orig, 0, &leave_kill_orig_data);

        restore_context(vmi, event);
    }

    vmi_register_event(vmi, &kill_step_event);
    return 0;
}

int introspect_process_kill (char *name, char *arg) {

    KILL_PID = atoi(arg);

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
     * We monitor the syscall sys_opctl, which is the most common one
     * Once this syscall happens, then the system will kill the process
     */
    vmi_translate_ksym2v(vmi, "schedule", &virt_schedule);

    memset(&kill_enter_event, 0, sizeof(vmi_event_t));

    kill_enter_event.type = VMI_EVENT_INTERRUPT;
    kill_enter_event.interrupt_event.intr = INT3;
    kill_enter_event.callback = kill_enter_cb;

    memset(&kill_step_event, 0, sizeof(vmi_event_t));
    kill_step_event.type = VMI_EVENT_SINGLESTEP;
    kill_step_event.callback = kill_step_cb;
    kill_step_event.ss_event.enable = 1;
    SET_VCPU_SINGLESTEP(kill_step_event.ss_event, 0);

    if(vmi_register_event(vmi, &kill_enter_event) == VMI_FAILURE) {
        printf("Could not install enter syscall handler.\n");
        goto exit;
    }

    if (VMI_FAILURE == vmi_read_32_va(vmi, virt_schedule, 0, &schedule_orig_data)) {
        printf("failed to read the original data.\n");
        vmi_destroy(vmi);
        return -1;
    }

    if (set_breakpoint(vmi, virt_schedule, 0) < 0) {
        printf("Could not set break points\n");
        goto exit;
    }

    while(!interrupted){
        if (vmi_events_listen(vmi, 1000) != VMI_SUCCESS) {
            printf("Error waiting for events, quitting...\n");
            interrupted = -1;
        }
    }

exit:

    if (VMI_FAILURE == vmi_write_32_va(vmi, virt_schedule, 0, &schedule_orig_data)) {
        printf("failed to write back the original data.\n");
    }

    vmi_destroy(vmi);
    return 0;
}
