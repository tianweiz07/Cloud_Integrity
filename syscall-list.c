#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>

#include <libvmi/libvmi.h>

int main(int argc, char **argv)
{
    vmi_instance_t vmi;
    addr_t sys_call_table_addr, sys_call_addr;
    addr_t stext, etext;

    char *name = argv[1];

    if (vmi_init(&vmi, VMI_AUTO | VMI_INIT_COMPLETE, name) == VMI_FAILURE) {
        printf("Failed to init LibVMI library.\n");
        return 1;
    }


    switch(vmi_get_ostype(vmi)) {
        case VMI_OS_LINUX:
            sys_call_table_addr = vmi_translate_ksym2v(vmi, "sys_call_table");
            break;
        case VMI_OS_WINDOWS:
            printf("Currently does not support Windows\n");
            goto error_exit;
        default:
            goto error_exit;
    }

    int i = 0;
    stext = vmi_translate_ksym2v(vmi, "_stext");
    etext = vmi_translate_ksym2v(vmi, "_etext");

    for (i=0; i<300; i++) {
        vmi_read_addr_va(vmi, sys_call_table_addr+i*8, 0, &sys_call_addr);
        if (sys_call_addr < stext || sys_call_addr > etext) {
            printf("sys_call_table[%d] address changed to 0x%x\n", i, (unsigned int)sys_call_addr);
        }
    }

error_exit:

    vmi_destroy(vmi);

    return 0;
}
