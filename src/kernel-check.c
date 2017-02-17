#include "vmi.h"

int introspect_kernel_check(char *name) {
    vmi_instance_t vmi;
    addr_t kernel_start, kernel_end;

    if (vmi_init(&vmi, VMI_XEN | VMI_INIT_COMPLETE, name) == VMI_FAILURE) {
        printf("Failed to init LibVMI library.\n");
        return 1;
    }

    /**
     * get kernel function boundary
     */
    kernel_start = vmi_translate_ksym2v(vmi, "_stext");
    kernel_end = vmi_translate_ksym2v(vmi, "_etext");


    MD5_CTX c;
    char buf[512];
    ssize_t bytes;
    unsigned char out[MD5_DIGEST_LENGTH];

    MD5_Init(&c);

    int i;
    for (i=kernel_start; i<kernel_end; i+= 512) {
        bytes = vmi_read_va(vmi, i, 0, buf, 512);
        MD5_Update(&c, buf, bytes);
    }


    MD5_Final(out, &c);

    printf("kernel section hash value: ");
    for (i=0; i<MD5_DIGEST_LENGTH; i++)
        printf("%x ", out[i]);
    printf("\n");
    


exit:
    vmi_destroy(vmi);
    return 0;
}
