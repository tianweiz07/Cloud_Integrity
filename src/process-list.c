#include "vmi.h"

int introspect_process_list (char *name) {
    addr_t list_head = 0, next_list_entry = 0, current_process = 0;
    vmi_pid_t pid = 0;
    char *procname = NULL;

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

    vmi_pause_vm(vmi);

    /**
     * get offsets of the kernel data structures
     * get the head of the task_struct 
     */

    switch(vmi_get_ostype(vmi)) {
        case VMI_OS_LINUX:
            vmi_get_offset(vmi, "linux_tasks", &tasks_offset);
            vmi_get_offset(vmi, "linux_name", &name_offset);
            vmi_get_offset(vmi, "linux_pid", &pid_offset);

            addr_t init_task_addr;
            vmi_translate_ksym2v(vmi, "init_task", &init_task_addr);

            list_head = init_task_addr + tasks_offset;

            break;
        case VMI_OS_WINDOWS:
            vmi_get_offset(vmi, "win_tasks", &tasks_offset);
            vmi_get_offset(vmi, "win_pname", &name_offset);
            vmi_get_offset(vmi, "win_pid", &pid_offset);

            vmi_translate_ksym2v(vmi, "PsActiveProcessHead", &list_head);
            break;
        default:
            goto exit;
    }


    if (tasks_offset == 0 || pid_offset == 0 || name_offset == 0) {
        printf("Failed to find offsets\n");
        goto exit;
    }

    next_list_entry = list_head;

    /** 
     * traverse the task lists and print out each process 
     */
    do {
        current_process = next_list_entry - tasks_offset;
        vmi_read_32_va(vmi, current_process + pid_offset, 0, (uint32_t*)&pid);
        procname = vmi_read_str_va(vmi, current_process + name_offset, 0);
        if (!procname) {
            printf("Failed to find procname\n");
            goto exit;
        }

        printf("[%5d] %s\n", pid, procname);

        free(procname);
        procname = NULL;

        if (vmi_read_addr_va(vmi, next_list_entry, 0, &next_list_entry) == VMI_FAILURE) {
            printf("Failed to read next pointer in loop at %"PRIx64"\n", next_list_entry);
            goto exit;
        }

    } while(next_list_entry != list_head);

exit:
    vmi_resume_vm(vmi);
    vmi_destroy(vmi);

    return 0;
}
