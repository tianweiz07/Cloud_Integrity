#include "vmi.h"

int introspect_procfs_check(char *name)
{
    addr_t init_net_addr, pde_addr, name_addr, tcp_addr, show_addr;
    addr_t stext, etext;
    char *filename = NULL;
    int got_tcp = 0;

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
     * /proc/network structure offsets. 
     * These offset values can be retrieved by running findproc tool inside the guest OS
     */
    unsigned long procnet_offset = 0x38;
    unsigned long subdir_offset = 0x50;
    unsigned long name_offset = 0x8;
    unsigned long next_offset = 0x40;
    unsigned long data_offset = 0x58;
    unsigned long show_offset = 0xf8;

    /**
     * get init_net address
     */
    vmi_translate_ksym2v(vmi, "init_net", &init_net_addr);

    /**
     * get /proc/network address
     */
    vmi_read_addr_va(vmi, init_net_addr+procnet_offset, 0, &pde_addr);
    vmi_read_addr_va(vmi, pde_addr + subdir_offset, 0, &pde_addr);

    /**
     * interate all the directories inside the /proc/network until getting the tcp directory
     */
    do {
        vmi_read_addr_va(vmi, pde_addr + name_offset, 0, &name_addr);
        filename = vmi_read_str_va(vmi, name_addr, 0);
        if (!strncmp(filename, "tcp", sizeof("tcp"))) {
                got_tcp = 1;
                break;
        }
        vmi_read_addr_va(vmi, pde_addr + next_offset, 0, &pde_addr);
    } while (pde_addr);

    if (!got_tcp)
        goto exit;

    /**
     * get the show function address
     */
    vmi_read_addr_va(vmi, pde_addr + data_offset, 0, &tcp_addr);
    vmi_read_addr_va(vmi, tcp_addr + show_offset, 0, &show_addr);
    
    /**
     * get the kernel function boundary
     */
    vmi_translate_ksym2v(vmi, "_stext", &stext);
    vmi_translate_ksym2v(vmi, "_etext", &etext);
    
    if (show_addr < stext || show_addr > etext) {
        printf("TCP4 seq_ops show has been changed to 0x%x\n", (unsigned int)show_addr);
    } else {
        printf("TCP4 seq_ops show is not changed\n");
    }

exit:
    vmi_destroy(vmi);

    return 0;
}
