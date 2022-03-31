#include "vmi.h"

int introspect_kernel_check(char *name) {
    addr_t kernel_start, kernel_end;

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

    /**
     * get kernel function boundary
     */
    vmi_translate_ksym2v(vmi, "_stext", &kernel_start);
    vmi_translate_ksym2v(vmi, "_etext", &kernel_end);


    MD5_CTX c;
    char buf[512];
    ssize_t bytes;
    unsigned char out[MD5_DIGEST_LENGTH];

    MD5_Init(&c);

    int i;
    for (i=kernel_start; i<kernel_end; i+= 512) {
        vmi_read_va(vmi, i, 0, 512, buf, &bytes);
        MD5_Update(&c, buf, bytes);
    }


    MD5_Final(out, &c);

    printf("kernel section hash value: ");
    for (i = 0; i < MD5_DIGEST_LENGTH; i++)
        printf("%x ", out[i]);
    printf("\n");
    


exit:
    vmi_destroy(vmi);
    return 0;
}
