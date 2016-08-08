#include "vmi.h"

int introspect_module_list(char *name) {
    vmi_instance_t vmi;
    addr_t next_module, list_head;
    char *modname = NULL;
    unicode_string_t *us = NULL;

    if (vmi_init(&vmi, VMI_XEN | VMI_INIT_COMPLETE, name) == VMI_FAILURE) {
        printf("Failed to init LibVMI library.\n");
        return 1;
    }

    vmi_pause_vm(vmi);

    /**
     * get the head of the module list
     */

    switch(vmi_get_ostype(vmi)) {
        case VMI_OS_LINUX:
            vmi_read_addr_ksym(vmi, "modules", &next_module);
            break;
        case VMI_OS_WINDOWS:
            vmi_read_addr_ksym(vmi, "PsLoadedModuleList", &next_module);
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
                modname = vmi_read_str_va(vmi, next_module + 16, 0);
                printf("%s\n", modname);
                free(modname);
                break;
            case VMI_OS_WINDOWS:
                us = vmi_read_unicode_str_va(vmi, next_module + 0x58, 0);
                unicode_string_t out = { 0 };
                if (us && VMI_SUCCESS == vmi_convert_str_encoding(us, &out, "UTF-8")) {
                    printf("%s\n", out.contents);
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
