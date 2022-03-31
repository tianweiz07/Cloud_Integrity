#include "vmi.h"

int introspect_module_list(char *name) {
    addr_t next_module, list_head;
    char *modname = NULL;
    addr_t offset;
    uint32_t size;
    int nameOffset;
    int addrOffset;
    int sizeOffset;

    unicode_string_t *us = NULL;

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


    vmi_pause_vm(vmi);

    /**
     * get the head of the module list
     */

    switch(vmi_get_ostype(vmi)) {
        case VMI_OS_LINUX:
            vmi_read_addr_ksym(vmi, "modules", &next_module);
            /**
             * get module structure offset. Using ./tool/findmodule
             */
            nameOffset = 0x10;
            addrOffset = 0x150;
            sizeOffset = 0x15c;
            break;
        case VMI_OS_WINDOWS:
            vmi_read_addr_ksym(vmi, "PsLoadedModuleList", &next_module);
            /**
             * get _LDR_DATA_TABLE_ENTRY structure offset
             */
            nameOffset = 0x58;
            addrOffset = 0x30;
            sizeOffset = 0x40;
            break;
        default:
            goto exit;
    }


    list_head = next_module;

    /**
     * traverse the module lists and print out each module
     */
    while (1) {
        addr_t tmp_next = 0;
        vmi_read_addr_va(vmi, next_module, 0, &tmp_next);

        if (list_head == tmp_next) {
            break;
        }

        switch(vmi_get_ostype(vmi)) {
            case VMI_OS_LINUX:
                modname = vmi_read_str_va(vmi, next_module + nameOffset, 0);
                vmi_read_64_va(vmi, next_module + addrOffset, 0, &offset);
                vmi_read_32_va(vmi, next_module + sizeOffset, 0, &size);
                printf("Module: %s Addr: 0x%" PRIx64 " Size: %d\n", modname, offset, size);
                free(modname);
                break;
            case VMI_OS_WINDOWS:
                us = vmi_read_unicode_str_va(vmi, next_module + nameOffset, 0);
                vmi_read_64_va(vmi, next_module + addrOffset, 0, &offset);
                vmi_read_32_va(vmi, next_module + sizeOffset, 0, &size);
                unicode_string_t out = { 0 };
                if (us && VMI_SUCCESS == vmi_convert_str_encoding(us, &out, "UTF-8")) {
                    printf("Module: %s Addr: 0x%" PRIx64 " Size: %d\n", out.contents, offset, size);
                    free(out.contents);
                }
                if (us)
                    vmi_free_unicode_str(us);
                break;
            default:
                goto exit;
        }

        next_module = tmp_next;
    }

exit:
    vmi_resume_vm(vmi);
    vmi_destroy(vmi);

    return 0;
}
