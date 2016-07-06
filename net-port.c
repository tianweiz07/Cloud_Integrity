#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>

#include <libvmi/libvmi.h>

int main(int argc, char **argv)
{
    vmi_instance_t vmi;

    char *name = argv[1];

    if (vmi_init(&vmi, VMI_AUTO | VMI_INIT_COMPLETE, name) == VMI_FAILURE) {
        printf("Failed to init LibVMI library.\n");
        return 1;
    }

    addr_t init_net_addr, pde_addr, name_addr, tcp_addr, show_addr;
    addr_t stext, etext;

    char *filename = NULL;
    int got_tcp = 0;

    /* These offset values can be retrieved by running findproc tool inside the guest OS */

    unsigned long procnet_offset = 0x38;
    unsigned long subdir_offset = 0x50;
    unsigned long name_offset = 0x8;
    unsigned long next_offset = 0x40;
    unsigned long data_offset = 0x58;
    unsigned long show_offset = 0xf8;

    switch(vmi_get_ostype(vmi)) {
        case VMI_OS_LINUX:
            init_net_addr = vmi_translate_ksym2v(vmi, "init_net");
            break;
        case VMI_OS_WINDOWS:
            printf("Currently does not support Windows\n");
            goto error_exit;
        default:
            goto error_exit;
    }

    vmi_read_addr_va(vmi, init_net_addr+procnet_offset, 0, &pde_addr);
    vmi_read_addr_va(vmi, pde_addr + subdir_offset, 0, &pde_addr);

    do {
        vmi_read_addr_va(vmi, pde_addr + name_offset, 0, &name_addr);
        filename = vmi_read_str_va(vmi, name_addr, 0);
        if (strncmp(filename, "tcp", sizeof("tcp")) == 0) {
                got_tcp = 1;
                break;
        }
        vmi_read_addr_va(vmi, pde_addr + next_offset, 0, &pde_addr);
    } while (pde_addr);

    if (!got_tcp)
        goto error_exit;

    vmi_read_addr_va(vmi, pde_addr + data_offset, 0, &tcp_addr);
    vmi_read_addr_va(vmi, tcp_addr + show_offset, 0, &show_addr);
    
    stext = vmi_translate_ksym2v(vmi, "_stext");
    etext = vmi_translate_ksym2v(vmi, "_etext");
    
    if (show_addr < stext || show_addr > etext) {
        printf("TCP4 seq_ops show has been changed to 0x%x\n", (unsigned int)show_addr);
    } else {
        printf("TCP4 seq_ops show is not changed\n");
    }

error_exit:

    vmi_destroy(vmi);

    return 0;
}
