#include "vmi.h"

#define NR_SYSCALL 300

int introspect_syscall_check(char *name) {
    vmi_instance_t vmi;
    addr_t sys_call_table_addr, sys_call_addr, stext, etext;
    int count_syscall = 0;

    if (vmi_init(&vmi, VMI_XEN | VMI_INIT_COMPLETE, name) == VMI_FAILURE) {
        printf("Failed to init LibVMI library.\n");
        return 1;
    }

    /**
     * get syscall table address 
     */
    sys_call_table_addr = vmi_translate_ksym2v(vmi, "sys_call_table");


    /**
     * get kernel function boundary
     */
    stext = vmi_translate_ksym2v(vmi, "_stext");
    etext = vmi_translate_ksym2v(vmi, "_etext");

    int i = 0;
    for (i=0; i<NR_SYSCALL; i++) {
        vmi_read_addr_va(vmi, sys_call_table_addr+i*8, 0, &sys_call_addr);
        if (sys_call_addr < stext || sys_call_addr > etext) {
            printf("sys_call_table[%d] address changed to 0x%x\n", i, (unsigned int)sys_call_addr);
            count_syscall ++;
        }
    }
    printf("%d syscalls have been hooked\n", count_syscall);

exit:
    vmi_destroy(vmi);
    return 0;
}
