#include "vmi.h"

int introspect_network_check(char *name)
{
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

    addr_t tcp_hashinfo_addr;
    addr_t node_addr;
    addr_t udp_table_addr;

    uint16_t sport;

    unsigned long hlistOffset = 0x40;
    unsigned long hlistLength = 0x10;
    unsigned long firstOffset = 0x8;
    unsigned long sportOffset = 0x28c;
    unsigned long nextOffset = 0x0;

    unsigned long uhlistOffset = 0x0;
    unsigned long uhlistLength = 0x10;
    unsigned long ufirstOffset = 0x0;

    vmi_translate_ksym2v(vmi, "tcp_hashinfo", &tcp_hashinfo_addr);
    vmi_translate_ksym2v(vmi, "udp_table", &udp_table_addr);

    int i;
    printf("TCP ports: \n");
    for (i=0; i<32; i++) {
        vmi_read_addr_va(vmi, tcp_hashinfo_addr+hlistOffset+i*hlistLength+firstOffset, 0, &node_addr);
        while (!((unsigned long)node_addr & 1)) {
            vmi_read_16_va(vmi, node_addr+sportOffset, 0, &sport);
            uint16_t port = ((sport & 0xFF) << 8) + (sport >> 8);
            printf("%" PRIu16 "\n",port);
            vmi_read_addr_va(vmi, node_addr+nextOffset, 0, &node_addr);
        }
    }

    printf("UDP ports: \n");
    addr_t hash_addr;
    for (i=0; i<1024; i++) {
        vmi_read_addr_va(vmi, udp_table_addr+uhlistOffset, 0, &hash_addr);
        vmi_read_addr_va(vmi, hash_addr+i*uhlistLength+ufirstOffset, 0, &node_addr);

        while (!((unsigned long)node_addr & 1)) {
            vmi_read_16_va(vmi, node_addr+sportOffset, 0, &sport);
            uint16_t port = ((sport & 0xFF) << 8) + (sport >> 8);
            printf("%" PRIu16 "\n",port);
            vmi_read_addr_va(vmi, node_addr+nextOffset, 0, &node_addr);
        }
    }

exit:
    vmi_destroy(vmi);

    return 0;
}
