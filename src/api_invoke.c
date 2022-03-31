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

vmi_event_t syscall_enter_event;
vmi_event_t syscall_step_event;

reg_t virt_lstar;

uint32_t syscall_orig_data;
uint32_t syscall1_orig_data;

static int interrupted = 0;

static void close_handler(int sig){
    interrupted = sig;
}

int flag = -1;

reg_t rax_orig, rbx_orig, rcx_orig, rdx_orig, rbp_orig, rsi_orig, rsp_orig, rip_orig;

#define BASE_ADDR 0x400000

/* Allocate 100 Bytes from the user space to fill in new data */
uint8_t str_orig[100];

/** 
 * Try to use this comand to redirect the process list to a file. But bash command does not work.
 * This is strange: calling the same function inside the guest kernel works. 
*/
//char *argv[] = {"/bin/bash", "-c", "/bin/ps aux > /tmp/list"};


/**
 * Currently cannot get stdout
 */
char *argv[] = {"/home/tianwez/hello", "hello", "world"};
uint64_t argv_ptr[4] = {BASE_ADDR, BASE_ADDR+20, BASE_ADDR+26, 0x0};

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

    /* Save the user data*/
    reg_t cr3;
    vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);
    
    vmi_pid_t pid = -1;
    vmi_dtb_to_pid(vmi, cr3, &pid);

    int i = 0;
    for (i=0; i<100; i++) {
        vmi_read_8_va(vmi, BASE_ADDR+i, pid, &(str_orig[i]));
    }

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

    /* Restore the user data */
    reg_t cr3;
    vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);
    
    vmi_pid_t pid = -1;
    vmi_dtb_to_pid(vmi, cr3, &pid);

    int i;
    for (i=0; i<100; i++) {
        vmi_write_8_va(vmi, BASE_ADDR+i, pid, &(str_orig[i]));
    }
}


void print_reg(vmi_instance_t vmi, vmi_event_t *event) {
    reg_t val;
    printf("--------------------------------------------------------\n");
    vmi_get_vcpureg(vmi, &val, RAX, event->vcpu_id); printf("RAX=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, RBX, event->vcpu_id); printf("RBX=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, RCX, event->vcpu_id); printf("RCX=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, RDX, event->vcpu_id); printf("RDX=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, RBP, event->vcpu_id); printf("RBP=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, RSI, event->vcpu_id); printf("RSI=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, RDI, event->vcpu_id); printf("RDI=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, RSP, event->vcpu_id); printf("RSP=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, R8, event->vcpu_id); printf("R8=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, R9, event->vcpu_id); printf("R9=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, R10, event->vcpu_id); printf("R10=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, R11, event->vcpu_id); printf("R11=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, R12, event->vcpu_id); printf("R12=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, R13, event->vcpu_id); printf("R13=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, R14, event->vcpu_id); printf("R14=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, R15, event->vcpu_id); printf("R15=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, RIP, event->vcpu_id); printf("RIP=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, RFLAGS, event->vcpu_id); printf("RFLAGS=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, CR0, event->vcpu_id); printf("CR0=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, CR2, event->vcpu_id); printf("CR2=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, CR3, event->vcpu_id); printf("CR3=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, CR4, event->vcpu_id); printf("CR4=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, XCR0, event->vcpu_id); printf("XCR0=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, DR0, event->vcpu_id); printf("DR0=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, DR1, event->vcpu_id); printf("DR1=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, DR2, event->vcpu_id); printf("DR2=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, DR3, event->vcpu_id); printf("DR3=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, DR6, event->vcpu_id); printf("DR6=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, DR7, event->vcpu_id); printf("DR7=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, CS_SEL, event->vcpu_id); printf("CS_SEL=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, DS_SEL, event->vcpu_id); printf("DS_SEL=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, ES_SEL, event->vcpu_id); printf("ES_SEL=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, FS_SEL, event->vcpu_id); printf("FS_SEL=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, GS_SEL, event->vcpu_id); printf("GS_SEL=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, SS_SEL, event->vcpu_id); printf("SS_SEL=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, TR_SEL, event->vcpu_id); printf("TR_SEL=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, LDTR_SEL, event->vcpu_id); printf("LDTR_SEL=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, CS_LIMIT, event->vcpu_id); printf("CS_LIMIT=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, DS_LIMIT, event->vcpu_id); printf("DS_LIMIT=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, ES_LIMIT, event->vcpu_id); printf("ES_LIMIT=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, FS_LIMIT, event->vcpu_id); printf("FS_LIMIT=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, GS_LIMIT, event->vcpu_id); printf("GS_LIMIT=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, SS_LIMIT, event->vcpu_id); printf("SS_LIMIT=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, TR_LIMIT, event->vcpu_id); printf("TR_LIMIT=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, LDTR_LIMIT, event->vcpu_id); printf("LDTR_LIMIT=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, IDTR_LIMIT, event->vcpu_id); printf("IDTR_LIMIT=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, GDTR_LIMIT, event->vcpu_id); printf("GDTR_LIMIT=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, CS_BASE, event->vcpu_id); printf("CS_BASE=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, DS_BASE, event->vcpu_id); printf("DS_BASE=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, ES_BASE, event->vcpu_id); printf("ES_BASE=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, FS_BASE, event->vcpu_id); printf("FS_BASE=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, GS_BASE, event->vcpu_id); printf("GS_BASE=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, SS_BASE, event->vcpu_id); printf("SS_BASE=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, TR_BASE, event->vcpu_id); printf("TR_BASE=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, LDTR_BASE, event->vcpu_id); printf("LDTR_BASE=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, IDTR_BASE, event->vcpu_id); printf("IDTR_BASE=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, GDTR_BASE, event->vcpu_id); printf("GDTR_BASE=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, CS_ARBYTES, event->vcpu_id); printf("CS_ARBYTES=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, DS_ARBYTES, event->vcpu_id); printf("DS_ARBYTES=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, ES_ARBYTES, event->vcpu_id); printf("ES_ARBYTES=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, FS_ARBYTES, event->vcpu_id); printf("FS_ARBYTES=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, GS_ARBYTES, event->vcpu_id); printf("GS_ARBYTES=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, SS_ARBYTES, event->vcpu_id); printf("SS_ARBYTES=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, TR_ARBYTES, event->vcpu_id); printf("TR_ARBYTES=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, LDTR_ARBYTES, event->vcpu_id); printf("LDTR_ARBYTES=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, SYSENTER_CS, event->vcpu_id); printf("SYSENTER_CS=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, SYSENTER_ESP, event->vcpu_id); printf("SYSENTER_ESP=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, SYSENTER_EIP, event->vcpu_id); printf("SYSENTER_EIP=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, SHADOW_GS, event->vcpu_id); printf("SHADOW_GS=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, MSR_FLAGS, event->vcpu_id); printf("MSR_FLAGS=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, MSR_LSTAR, event->vcpu_id); printf("MSR_LSTAR=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, MSR_CSTAR, event->vcpu_id); printf("MSR_CSTAR=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, MSR_SYSCALL_MASK, event->vcpu_id); printf("MSR_SYSCALL_MASK=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, MSR_EFER, event->vcpu_id); printf("MSR_EFER=0x%x\n", (int)val);
    vmi_get_vcpureg(vmi, &val, MSR_TSC_AUX, event->vcpu_id); printf("MSR_TSC_AUX=0x%x\n", (int)val);
}


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



event_response_t syscall_step_cb(vmi_instance_t vmi, vmi_event_t *event) {

    if (flag == 0) {

        save_context(vmi, event);

        reg_t cr3;
        vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);
        vmi_pid_t pid = -1;
        vmi_dtb_to_pid(vmi, cr3, &pid);


        /* Insert new data into user memory space */
        int i = 0;
        for (i=0; i<20; i++) {
            vmi_write_8_va(vmi, BASE_ADDR+i, pid, &(argv[0][i]));
        }
        for (i=0; i<6; i++) {
            vmi_write_8_va(vmi, BASE_ADDR+20+i, pid, &(argv[1][i]));
        }
        for (i=0; i<6; i++) {
            vmi_write_8_va(vmi, BASE_ADDR+26+i, pid, &(argv[2][i]));
        }

        for (i=0; i<4; i++) {
            vmi_write_64_va(vmi, BASE_ADDR+32+i*8, pid, &(argv_ptr[i]));
        }


        /* Modify the registers of parameters */
        vmi_set_vcpureg(vmi, BASE_ADDR, RDI, event->vcpu_id);
        vmi_set_vcpureg(vmi, BASE_ADDR+32, RSI, event->vcpu_id);
        vmi_set_vcpureg(vmi, BASE_ADDR+56, RDX, event->vcpu_id);
        vmi_set_vcpureg(vmi, 0x2, RCX, event->vcpu_id);

        /* Modify the registers of stack */
        vmi_set_vcpureg(vmi, rsp_orig-8, RSP, event->vcpu_id);
        vmi_write_64_va(vmi, rsp_orig-8, 0, &rip_orig);

        addr_t addr;
        vmi_translate_ksym2v(vmi, "call_usermodehelper", &addr);
        vmi_set_vcpureg(vmi, addr, RIP, event->vcpu_id);

        vmi_read_32_va(vmi, rip_orig, 0, &syscall1_orig_data);
        set_breakpoint(vmi, rip_orig, 0);

    } else if (flag == 1) {
        interrupted = -1;
    }

    vmi_clear_event(vmi, &syscall_step_event, NULL);

    return 0;
}


event_response_t syscall_enter_cb(vmi_instance_t vmi, vmi_event_t *event){
    event->interrupt_event.reinject = 0;

    if (event->interrupt_event.gla == virt_lstar) {
        flag = 0;
        if (VMI_FAILURE == vmi_write_32_va(vmi, virt_lstar, 0, &syscall_orig_data)) {
            printf("failed to write memory.\n");
            exit(1);
        }
    } else if (event->interrupt_event.gla == rip_orig) {

        flag = 1;        
        vmi_write_32_va(vmi, rip_orig, 0, &syscall1_orig_data);

        reg_t cr3;
        vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);
        vmi_pid_t pid = -1;
        vmi_dtb_to_pid(vmi, cr3, &pid);

        restore_context(vmi, event);
    }

    vmi_register_event(vmi, &syscall_step_event);
    return 0;
}

int main (int argc, char **argv) {

    char *name = argv[1];

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


    printf("LibVMI init succeeded!\n");
    memset(&syscall_enter_event, 0, sizeof(vmi_event_t));

    vmi_translate_ksym2v(vmi, "sys_ioctl", &virt_lstar);

    memset(&syscall_enter_event, 0, sizeof(vmi_event_t));

    syscall_enter_event.type = VMI_EVENT_INTERRUPT;
    syscall_enter_event.interrupt_event.intr = INT3;
    syscall_enter_event.callback = syscall_enter_cb;

    memset(&syscall_step_event, 0, sizeof(vmi_event_t));
    syscall_step_event.type = VMI_EVENT_SINGLESTEP;
    syscall_step_event.callback = syscall_step_cb;
    syscall_step_event.ss_event.enable = 1;
    SET_VCPU_SINGLESTEP(syscall_step_event.ss_event, 0);

    if(vmi_register_event(vmi, &syscall_enter_event) == VMI_FAILURE) {
        printf("Could not install enter syscall handler.\n");
        goto exit;
    }

    if (VMI_FAILURE == vmi_read_32_va(vmi, virt_lstar, 0, &syscall_orig_data)) {
        printf("failed to read the original data.\n");
        vmi_destroy(vmi);
        return -1;
    }

    if (set_breakpoint(vmi, virt_lstar, 0) < 0) {
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

    if (VMI_FAILURE == vmi_write_32_va(vmi, virt_lstar, 0, &syscall_orig_data)) {
        printf("failed to write back the original data.\n");
    }

    vmi_destroy(vmi);
    return 0;
}
