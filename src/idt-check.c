#include "vmi.h"

int introspect_idt_check(char *name) {
    vmi_instance_t vmi;
    addr_t idt_addr, int_addr, kernel_start, kernel_end;
    int count_int = 0;

    uint64_t num_int = 0;
    char **int_index = NULL;;


    char _line[256];
    char _name[256];
    int _index[256];

    FILE *_file = fopen("interrupt_index", "r");
    while(fgets(_line, sizeof(_line), _file) != NULL){
        sscanf(_line, "%d\t%s", _index, _name);
        int_index = realloc(int_index, sizeof(char*) * ++num_int);
        int_index[num_int-1] = (char*) malloc(256);
        strcpy(int_index[num_int-1], _name);
    }
    fclose(_file);


    if (vmi_init(&vmi, VMI_XEN | VMI_INIT_COMPLETE, name) == VMI_FAILURE) {
        printf("Failed to init LibVMI library.\n");
        return 1;
    }


    vmi_get_vcpureg(vmi, &idt_addr, IDTR_BASE, 0);


    addr_t ntoskrnl, kernel_size;

    switch(vmi_get_ostype(vmi)) {
        case VMI_OS_LINUX:
            kernel_start = vmi_translate_ksym2v(vmi, "_stext");
            kernel_end = vmi_translate_ksym2v(vmi, "_etext");

            break;
        case VMI_OS_WINDOWS:
            vmi_read_addr_ksym(vmi, "PsLoadedModuleList", &ntoskrnl);
            vmi_read_64_va(vmi, ntoskrnl + 0x30, 0, &kernel_start);
            vmi_read_64_va(vmi, ntoskrnl + 0x40, 0, &kernel_size);
            kernel_end = kernel_start + kernel_size;

            break;
        default:
            goto exit;
    }

    int i = 0;
    uint16_t addr1, addr2;
    uint32_t addr3;
    for (i=0; i<num_int; i++) {
        vmi_read_16_va(vmi, idt_addr+i*16, 0, &addr1);
        vmi_read_16_va(vmi, idt_addr+i*16+6, 0, &addr2);
        vmi_read_32_va(vmi, idt_addr+i*16+8, 0, &addr3);
        int_addr = ((addr_t)addr3 << 32) + ((addr_t)addr2 << 16) + ((addr_t)addr1);

        if ((int_addr < kernel_start || int_addr > kernel_end) && (strcmp(int_index[i], "unknown"))) {
            printf("interrupt handler %s address changed to 0x%" PRIx64 "\n", int_index[i], int_addr);
            count_int ++;
        }
    }

    printf("%d interrupt handlers have been hooked\n", count_int);

exit:
    vmi_destroy(vmi);
    return 0;
}
