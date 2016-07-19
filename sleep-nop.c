#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <inttypes.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <openssl/md5.h>



#include <libvmi/libvmi.h>
#include <libvmi/events.h>

static int interrupted = 0;

addr_t sys_execve_addr1;
addr_t sys_execve_addr2;

vmi_event_t syscall_sysenter_event;
vmi_event_t single_event;

uint32_t orig_data1;
uint32_t orig_data2;

vmi_pid_t pid = -1;
char *procname;

/* task_struct offsets */
unsigned long tasks_offset;
unsigned long pid_offset;
unsigned long name_offset;

event_response_t single_step_cb(vmi_instance_t vmi, vmi_event_t *event) {

    syscall_sysenter_event.interrupt_event.reinject = 1;
    if (set_breakpoint(vmi, sys_execve_addr1, 0) < 0) {
        fprintf(stderr, "Could not set break points\n");
        exit(1);
    }
    
    if (set_breakpoint(vmi, sys_execve_addr2, 0) < 0) {
        fprintf(stderr, "Could not set break points\n");
        exit(1);
    }
    
    vmi_clear_event(vmi, &single_event, NULL);
    return 0;
}

int find_name(vmi_instance_t vmi, vmi_pid_t pid, char *name) {
    addr_t list_head = 0, next_list_entry = 0, current_process = 0;
    vmi_pid_t pid1 = 0;

    list_head = vmi_translate_ksym2v(vmi, "init_task") + tasks_offset;
    next_list_entry = list_head;

    do {
        current_process = next_list_entry - tasks_offset;
        vmi_read_32_va(vmi, current_process + pid_offset, 0, (uint32_t*)&pid1);
        if (pid1 == pid) {
            strcpy(name, vmi_read_str_va(vmi, current_process + name_offset, 0));
            if (!name) {
                printf("Failed to find procname\n");
                return -1;;
            }
            return 0;
        }
        status_t status = vmi_read_addr_va(vmi, next_list_entry, 0, &next_list_entry);
        if (status == VMI_FAILURE) {
            printf("Failed to read next pointer in loop at %"PRIx64"\n", next_list_entry);
            return -1;
        }
    } while(next_list_entry != list_head);
    return -1;
}

event_response_t syscall_sysenter_cb(vmi_instance_t vmi, vmi_event_t *event){
    reg_t rax, cr3, rsp;
    vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);
    vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rsp, RSP, event->vcpu_id);

    if (event->interrupt_event.gla == sys_execve_addr1 || event->interrupt_event.gla == sys_execve_addr2) {
        pid = vmi_dtb_to_pid(vmi, cr3);

        char name[256] = "";
        if (find_name(vmi, pid, name) < 0) {
            printf("Cannot find the processes\n");
            return -1;
        }
        
        if (!strcmp(name, procname)) {

            vmi_set_vcpureg(vmi, rsp+8, RSP, event->vcpu_id);
            vmi_set_vcpureg(vmi, 0, RAX, event->vcpu_id);
            uint64_t rip;
            vmi_read_64_va(vmi, rsp, pid, &rip);
            vmi_set_vcpureg(vmi, rip, RIP, event->vcpu_id);
        }
       
    }

    event->interrupt_event.reinject = 0;
    if (VMI_FAILURE == vmi_write_32_va(vmi, sys_execve_addr1, 0, &orig_data1)) {
        fprintf(stderr, "failed to write memory.\n");
        exit(1);
    }

    if (VMI_FAILURE == vmi_write_32_va(vmi, sys_execve_addr2, 0, &orig_data2)) {
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

    if(argc < 3){
        fprintf(stderr, "Usage: events_example <name of VM> <PID of process to track {optional}>\n");
        exit(1);
    }

    char *name = NULL;
    name = argv[1];
    procname = argv[2];

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


    tasks_offset = vmi_get_offset(vmi, "linux_tasks");
    name_offset = vmi_get_offset(vmi, "linux_name");
    pid_offset = vmi_get_offset(vmi, "linux_pid");

    sys_execve_addr1 = vmi_translate_ksym2v(vmi, "sys_nanosleep");
    sys_execve_addr2 = vmi_translate_ksym2v(vmi, "sys_clock_nanosleep");

    memset(&syscall_sysenter_event, 0, sizeof(vmi_event_t));
    syscall_sysenter_event.type = VMI_EVENT_INTERRUPT;
    syscall_sysenter_event.interrupt_event.intr = INT3;
    syscall_sysenter_event.callback = syscall_sysenter_cb;

    memset(&single_event, 0, sizeof(vmi_event_t));
    single_event.type = VMI_EVENT_SINGLESTEP;
    single_event.callback = single_step_cb;
    single_event.ss_event.enable = 1;
    SET_VCPU_SINGLESTEP(single_event.ss_event, 0);

    if (VMI_FAILURE == vmi_read_32_va(vmi, sys_execve_addr1, 0, &orig_data1)) {
        printf("failed to read memory1.\n");
        vmi_destroy(vmi);
        return -1;
    }

    if (VMI_FAILURE == vmi_read_32_va(vmi, sys_execve_addr2, 0, &orig_data2)) {
        printf("failed to read memory2.\n");
        vmi_destroy(vmi);
        return -1;
    }

    if(vmi_register_event(vmi, &syscall_sysenter_event) == VMI_FAILURE) {
        fprintf(stderr, "Could not install sysenter syscall handler.\n");
        goto leave;
    }

    if (set_breakpoint(vmi, sys_execve_addr1, 0) < 0) {
        fprintf(stderr, "Could not set break points\n");
        goto leave;
    }

    if (set_breakpoint(vmi, sys_execve_addr2, 0) < 0) {
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
    if (VMI_FAILURE == vmi_write_32_va(vmi, sys_execve_addr1, 0, &orig_data1)) {
        fprintf(stderr, "failed to write memory.\n");
        exit(1);
    }

    if (VMI_FAILURE == vmi_write_32_va(vmi, sys_execve_addr2, 0, &orig_data2)) {
        fprintf(stderr, "failed to write memory.\n");
        exit(1);
    }

    vmi_destroy(vmi);

    return 0;
}
