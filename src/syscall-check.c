#include "vmi.h"

int introspect_syscall_check(char *name) {
    vmi_instance_t vmi;
    addr_t sys_call_table_addr, sys_call_addr, kernel_start, kernel_end;
    int count_syscall = 0;

    uint32_t num_sys = 0;
    char **sys_index = NULL;;

    char _line[256];
    char _name[256];
    int _index[256];

    FILE *_file = fopen("syscall_index", "r");
    while(fgets(_line, sizeof(_line), _file) != NULL){
        sscanf(_line, "%d\t%s", _index, _name);
        sys_index = realloc(sys_index, sizeof(char*) * ++num_sys);
        sys_index[num_sys-1] = (char*) malloc(256);
        strcpy(sys_index[num_sys-1], _name);
    }
    fclose(_file);


    if (vmi_init(&vmi, VMI_XEN | VMI_INIT_COMPLETE, name) == VMI_FAILURE) {
        printf("Failed to init LibVMI library.\n");
        return 1;
    }



    addr_t ntoskrnl, kernel_size;
    addr_t SSDT;
    int start_index, end_index;


    switch(vmi_get_ostype(vmi)) {
        case VMI_OS_LINUX:
            /**
             * get syscall table address 
             */
            sys_call_table_addr = vmi_translate_ksym2v(vmi, "sys_call_table");
            /**
             * get kernel function boundary
             */
            kernel_start = vmi_translate_ksym2v(vmi, "_stext");
            kernel_end = vmi_translate_ksym2v(vmi, "_etext");

            start_index = 0;
            end_index = num_sys;

            break;
        case VMI_OS_WINDOWS:
            SSDT = vmi_translate_ksym2v(vmi, "KeServiceDescriptorTable");
            vmi_read_addr_va(vmi, SSDT, 0, &sys_call_table_addr);
            vmi_read_32_va(vmi, SSDT+16, 0, &num_sys);

            vmi_read_addr_ksym(vmi, "PsLoadedModuleList", &ntoskrnl);
            vmi_read_64_va(vmi, ntoskrnl + 0x30, 0, &kernel_start);
            vmi_read_64_va(vmi, ntoskrnl + 0x40, 0, &kernel_size);
            kernel_end = kernel_start + kernel_size;

            /**
             * I don't know why the first 217 entries do not store the syscall pointer. 
             */
            start_index = 217;
            end_index = num_sys;
            break;
        default:
            goto exit;
    }
            


    int i = 0;
    for (i=start_index; i<end_index; i++) {
        vmi_read_addr_va(vmi, sys_call_table_addr+i*8, 0, &sys_call_addr);
        if (sys_call_addr < kernel_start || sys_call_addr > kernel_end) {
            printf("sys_call %s address changed to 0x%" PRIx64 "\n", sys_index[i], sys_call_addr);
            count_syscall ++;
        }
    }

    printf("%d syscalls have been hooked\n", count_syscall);

exit:
    vmi_destroy(vmi);
    return 0;
}
