#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>

#include <libvmi/libvmi.h>

int main(int argc, char **argv)
{
    vmi_instance_t vmi;
    uint32_t offset;
    addr_t next_module, list_head;

    char *name = argv[1];

    if (vmi_init(&vmi, VMI_AUTO | VMI_INIT_COMPLETE, name) == VMI_FAILURE) {
        printf("Failed to init LibVMI library.\n");
        return 1;
    }

    vmi_pause_vm(vmi);

    switch(vmi_get_ostype(vmi)) {
        case VMI_OS_LINUX:
            vmi_read_addr_ksym(vmi, "modules", &next_module);
            break;
        case VMI_OS_WINDOWS:
            vmi_read_addr_ksym(vmi, "PsLoadedModuleList", &next_module);
            break;
        default:
            goto error_exit;
    }

    list_head = next_module;

    while (1) {
        addr_t tmp_next = 0;
        vmi_read_addr_va(vmi, next_module, 0, &tmp_next);

        if (list_head == tmp_next) {
            break;
        }

        if (VMI_OS_LINUX == vmi_get_ostype(vmi)) {
            char *modname = NULL;

            if (VMI_PM_IA32E == vmi_get_page_mode(vmi)) {
                modname = vmi_read_str_va(vmi, next_module + 16, 0);
            }
            else {
                modname = vmi_read_str_va(vmi, next_module + 8, 0);
            }
            printf("%s\n", modname);
            free(modname);
        }
        else if (VMI_OS_WINDOWS == vmi_get_ostype(vmi)) {

            unicode_string_t *us = NULL;

            /*
             * The offset 0x58 and 0x2c is the offset in the _LDR_DATA_TABLE_ENTRY structure
             * to the BaseDllName member.
             * These offset values are stable (at least) between XP and Windows 7.
             */

            if (VMI_PM_IA32E == vmi_get_page_mode(vmi)) {
                us = vmi_read_unicode_str_va(vmi, next_module + 0x58, 0);
            } else {
                us = vmi_read_unicode_str_va(vmi, next_module + 0x2c, 0);
            }

            unicode_string_t out = { 0 };
            //         both of these work
            if (us &&
                VMI_SUCCESS == vmi_convert_str_encoding(us, &out,
                                                        "UTF-8")) {
                printf("%s\n", out.contents);
                //            if (us && 
                //                VMI_SUCCESS == vmi_convert_string_encoding (us, &out, "WCHAR_T")) {
                //                printf ("%ls\n", out.contents);
                free(out.contents);
            }   // if
            if (us)
                vmi_free_unicode_str(us);
        }
        next_module = tmp_next;
    }

error_exit:
    vmi_resume_vm(vmi);

    vmi_destroy(vmi);

    return 0;
}
