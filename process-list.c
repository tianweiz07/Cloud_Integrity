#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <inttypes.h>

#include <libvmi/libvmi.h>

int main (int argc, char **argv)
{
    vmi_instance_t vmi;
    unsigned char *memory = NULL;
    uint32_t offset;
    addr_t list_head = 0, next_list_entry = 0;
    addr_t current_process = 0;
    addr_t tmp_next = 0;
    char *procname = NULL;
    vmi_pid_t pid = 0;
    unsigned long tasks_offset = 0, pid_offset = 0, name_offset = 0;
    status_t status;

    if (argc != 2) {
        printf("Usage: %s <vmname>\n", argv[0]);
        return 1;
    } 

    char *name = argv[1];

    if (vmi_init(&vmi, VMI_AUTO | VMI_INIT_COMPLETE, name) == VMI_FAILURE) {
        printf("Failed to init LibVMI library.\n");
        return 1;
    }

    if (VMI_OS_LINUX == vmi_get_ostype(vmi)) {
        tasks_offset = vmi_get_offset(vmi, "linux_tasks");
        name_offset = vmi_get_offset(vmi, "linux_name");
        pid_offset = vmi_get_offset(vmi, "linux_pid");
    }
    else if (VMI_OS_WINDOWS == vmi_get_ostype(vmi)) {
        tasks_offset = vmi_get_offset(vmi, "win_tasks");
        name_offset = vmi_get_offset(vmi, "win_pname");
        pid_offset = vmi_get_offset(vmi, "win_pid");
    }

    if (0 == tasks_offset) {
        printf("Failed to find win_tasks\n");
        goto error_exit;
    }
    if (0 == pid_offset) {
        printf("Failed to find win_pid\n");
        goto error_exit;
    }
    if (0 == name_offset) {
        printf("Failed to find win_pname\n");
        goto error_exit;
    }

    if (vmi_pause_vm(vmi) != VMI_SUCCESS) {
        printf("Failed to pause VM\n");
        goto error_exit;
    } 

    char *name2 = vmi_get_name(vmi);

    if (VMI_FILE != vmi_get_access_mode(vmi)) {
        uint64_t id = vmi_get_vmid(vmi);

        printf("Process listing for VM %s (id=%"PRIu64")\n", name2, id);
    }
    else {
        printf("Process listing for file %s\n", name2);
    }
    free(name2);
    if (VMI_OS_LINUX == vmi_get_ostype(vmi)) {
        list_head = vmi_translate_ksym2v(vmi, "init_task") + tasks_offset;
    }
    else if (VMI_OS_WINDOWS == vmi_get_ostype(vmi)) {

        if(VMI_FAILURE == vmi_read_addr_ksym(vmi, "PsActiveProcessHead", &list_head)) {
            printf("Failed to find PsActiveProcessHead\n");
            goto error_exit;
        }
    }

    next_list_entry = list_head;

    do {

        current_process = next_list_entry - tasks_offset;

        vmi_read_32_va(vmi, current_process + pid_offset, 0, (uint32_t*)&pid);

        procname = vmi_read_str_va(vmi, current_process + name_offset, 0);

        if (!procname) {
            printf("Failed to find procname\n");
            goto error_exit;
        }

        printf("[%5d] %s (struct addr:%"PRIx64")\n", pid, procname, current_process);
        if (procname) {
            free(procname);
            procname = NULL;
        }

        status = vmi_read_addr_va(vmi, next_list_entry, 0, &next_list_entry);
        if (status == VMI_FAILURE) {
            printf("Failed to read next pointer in loop at %"PRIx64"\n", next_list_entry);
            goto error_exit;
        }

    } while(next_list_entry != list_head);

error_exit:
    vmi_resume_vm(vmi);

    vmi_destroy(vmi);



    return 0;
}
