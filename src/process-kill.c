#include "vmi.h"

vmi_event_t kill_enter_event;
vmi_event_t kill_step_event;

addr_t virt_ioctl;

uint32_t ioctl_orig_data;
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

        vmi_set_vcpureg(vmi, vmi_translate_ksym2v(vmi, "sys_kill"), RIP, event->vcpu_id);

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

    if (event->interrupt_event.gla == virt_ioctl) {
        kill_flag = 0;
        if (VMI_FAILURE == vmi_write_32_va(vmi, virt_ioctl, 0, &ioctl_orig_data)) {
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
    if (vmi_init(&vmi, VMI_XEN | VMI_INIT_COMPLETE | VMI_INIT_EVENTS, name) == VMI_FAILURE){
        printf("Failed to init LibVMI library.\n");
        vmi_destroy(vmi);
        return 1;
    }

    /**
     * We monitor the syscall sys_opctl, which is the most common one
     * Once this syscall happens, then the system will kill the process
     */
    virt_ioctl = vmi_translate_ksym2v(vmi, "sys_ioctl");

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

    if (VMI_FAILURE == vmi_read_32_va(vmi, virt_ioctl, 0, &ioctl_orig_data)) {
        printf("failed to read the original data.\n");
        vmi_destroy(vmi);
        return -1;
    }

    if (set_breakpoint(vmi, virt_ioctl, 0) < 0) {
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

    if (VMI_FAILURE == vmi_write_32_va(vmi, virt_ioctl, 0, &ioctl_orig_data)) {
        printf("failed to write back the original data.\n");
    }

    vmi_destroy(vmi);
    return 0;
}
