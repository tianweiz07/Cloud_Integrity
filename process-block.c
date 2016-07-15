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

addr_t sys_execve_addr;

vmi_event_t syscall_sysenter_event;
vmi_event_t single_event;

uint32_t orig_data;
vmi_pid_t pid = -1;

/* task_struct offsets */
unsigned long tasks_offset;
unsigned long pid_offset;
unsigned long name_offset;

/* file struct offset */
unsigned long fs_offset;
unsigned long dentry_offset;
unsigned long parent_offset;
unsigned long iname_offset;


event_response_t single_step_cb(vmi_instance_t vmi, vmi_event_t *event) {

    syscall_sysenter_event.interrupt_event.reinject = 1;
    if (set_breakpoint(vmi, sys_execve_addr, 0) < 0) {
        fprintf(stderr, "Could not set break points\n");
        exit(1);
    }
    
    vmi_clear_event(vmi, &single_event, NULL);
    return 0;
}

int find_absolute_path(vmi_instance_t vmi, char *filename) {
    char **path = NULL;
    char *p = strtok(filename, "/");
    int n = 0, i;
    while (p) {
        path = realloc(path, sizeof(char*) * ++n);
        path[n-1] = p;
        p = strtok(NULL, "/");
    }

    char **abs_path = NULL;
    int abs_n = 0;
    int flag = 0;
    for (i=n-1; i>=0; i--) {
        if(!strcmp(path[i], "."))
            continue;
        if(!strcmp(path[i], "..")) {
            flag = 1;
            continue;
        }
        if (flag == 0) {
            abs_path = realloc(abs_path, sizeof(char*) * ++abs_n);
            abs_path[abs_n-1] = (char *)malloc(256);
            strcpy(abs_path[abs_n-1], path[i]);
        }
    }

    /* The parameter is a relative path. Convert it to absolute path */

    if ((!strcmp(path[0], "."))||(!strcmp(path[0], ".."))) {

        addr_t list_head = 0, next_list_entry = 0, current_process = 0;
        vmi_pid_t pid1 = 0;

        list_head = vmi_translate_ksym2v(vmi, "init_task") + tasks_offset;
        next_list_entry = list_head;

        do {
            current_process = next_list_entry - tasks_offset;
            vmi_read_32_va(vmi, current_process + pid_offset, 0, (uint32_t*)&pid1);
            if (pid1 == pid) {
                char *procname = NULL, *dirname = NULL;
                procname = vmi_read_str_va(vmi, current_process + name_offset, 0);
                if (!procname) {
                    printf("Failed to find procname\n");
                    return -1;;
                }

                addr_t fs_addr, dentry_addr;
                vmi_read_addr_va(vmi, current_process+fs_offset, 0, &fs_addr);
                vmi_read_addr_va(vmi, fs_addr+dentry_offset, 0, &dentry_addr);
                dirname = vmi_read_str_va(vmi, dentry_addr+iname_offset, 0);
                while (strcmp("/", dirname)) {
                    if (flag == 1) {
                        flag = 0;
                    } else {
                        abs_path = realloc(abs_path, sizeof(char*) * ++abs_n);
                        abs_path[abs_n-1] = (char *)malloc(100);
                        strcpy(abs_path[abs_n-1], dirname);
                    }
                    vmi_read_addr_va(vmi, dentry_addr+parent_offset, 0, &dentry_addr);
                    dirname = vmi_read_str_va(vmi, dentry_addr+iname_offset, 0);
                }
                break;
            }
            status_t status = vmi_read_addr_va(vmi, next_list_entry, 0, &next_list_entry);
            if (status == VMI_FAILURE) {
                printf("Failed to read next pointer in loop at %"PRIx64"\n", next_list_entry);
                return -1;
            }
        } while(next_list_entry != list_head);
    }

    for (i=0; i<abs_n; i++)
        printf("%s\n", abs_path[i]);
    return 0;
}

event_response_t syscall_sysenter_cb(vmi_instance_t vmi, vmi_event_t *event){
    reg_t rdi, rax, cr3, rsp;
    vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rdi, RDI, event->vcpu_id);
    vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rsp, RSP, event->vcpu_id);

    if (event->interrupt_event.gla == sys_execve_addr) {
        pid = vmi_dtb_to_pid(vmi, cr3);
        char *filename = NULL;
        filename = vmi_read_str_va(vmi, rdi, pid);
        printf("Process[%d] invokes sys_execve: %s\n", pid, filename);

	/* This method can change the API's parameter into invalid, via modifying RDI registers. */
/*
        if (!strcmp(filename, "./hello")) {
            uint32_t var = 0x0;
            vmi_write_32_va(vmi, rdi, pid, &var);
        }
*/
        /* This method change the code path by modifying the RIP register, and return values in RAX */
        if (!strcmp(filename, "./hello")) {
            // Pop RIP out of stack
            vmi_set_vcpureg(vmi, rsp-8, RSP, event->vcpu_id);
            // Invalid the return value. If the return value is a pointer, can change to 0x0
            vmi_set_vcpureg(vmi, -1, RAX, event->vcpu_id);
            // Change the RIP to the old one
            uint64_t rip;
            vmi_read_64_va(vmi, rsp, pid, &rip);
            vmi_set_vcpureg(vmi, rip, RIP, event->vcpu_id);
        }

        find_absolute_path(vmi, filename);
    }


    event->interrupt_event.reinject = 0;
    if (VMI_FAILURE == vmi_write_32_va(vmi, sys_execve_addr, 0, &orig_data)) {
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


    tasks_offset = vmi_get_offset(vmi, "linux_tasks");
    name_offset = vmi_get_offset(vmi, "linux_name");
    pid_offset = vmi_get_offset(vmi, "linux_pid");

    /* file struct offsets can be obtained by running findpwd */
    fs_offset = 0x530;
    dentry_offset = 0x28;
    parent_offset = 0x28;
    iname_offset = 0xa0;


    sys_execve_addr = vmi_translate_ksym2v(vmi, "do_execve");
    printf("sys_execve address is 0x%x\n", (unsigned int)sys_execve_addr);

    memset(&syscall_sysenter_event, 0, sizeof(vmi_event_t));
    syscall_sysenter_event.type = VMI_EVENT_INTERRUPT;
    syscall_sysenter_event.interrupt_event.intr = INT3;
    syscall_sysenter_event.callback = syscall_sysenter_cb;

    memset(&single_event, 0, sizeof(vmi_event_t));
    single_event.type = VMI_EVENT_SINGLESTEP;
    single_event.callback = single_step_cb;
    single_event.ss_event.enable = 1;
    SET_VCPU_SINGLESTEP(single_event.ss_event, 0);

    if (VMI_FAILURE == vmi_read_32_va(vmi, sys_execve_addr, 0, &orig_data)) {
        printf("failed to read memory.\n");
        vmi_destroy(vmi);
        return -1;
    }

    if(vmi_register_event(vmi, &syscall_sysenter_event) == VMI_FAILURE) {
        fprintf(stderr, "Could not install sysenter syscall handler.\n");
        goto leave;
    }

    if (set_breakpoint(vmi, sys_execve_addr, 0) < 0) {
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
    if (VMI_FAILURE == vmi_write_32_va(vmi, sys_execve_addr, 0, &orig_data)) {
        fprintf(stderr, "failed to write memory.\n");
        exit(1);
    }

    vmi_destroy(vmi);

    return 0;
}
