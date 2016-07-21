#include "vmi.h"

int introspect_module_list(char *name) {
    vmi_instance_t vmi;
    addr_t next_module, list_head;
    char *modname = NULL;

    if (vmi_init(&vmi, VMI_XEN | VMI_INIT_COMPLETE, name) == VMI_FAILURE) {
        printf("Failed to init LibVMI library.\n");
        return 1;
    }

    vmi_pause_vm(vmi);

    /**
     * get the head of the module list
     */
    vmi_read_addr_ksym(vmi, "modules", &next_module);

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

        modname = vmi_read_str_va(vmi, next_module + 16, 0);
        printf("%s\n", modname);
        free(modname);
        next_module = tmp_next;
    }

exit:
    vmi_resume_vm(vmi);
    vmi_destroy(vmi);

    return 0;
}
