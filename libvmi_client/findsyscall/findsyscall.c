#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>

#define MYMODNAME "FindSyscall "

static int my_init_module(void);
static void my_cleanup_module(void);

static int my_init_module(void) {
        int i;
        unsigned long syscall_addr;
	static unsigned long *__sys_call_table_ptr;

        __sys_call_table_ptr = (void *) kallsyms_lookup_name("sys_call_table");

        if (__sys_call_table_ptr == NULL) {
                printk("Unable to get sys_call_table address. Aborting");
                return 0;
        }

        for (i = 0; i < 10; i++) {
                syscall_addr = __sys_call_table_ptr[i];
                printk("[0x%x] sys_call_table[%d]: 0x%x\n", (unsigned int)(&(__sys_call_table_ptr[i])), i, (unsigned int)syscall_addr);
        }

        return 0;
}

static void my_cleanup_module(void){
    printk(KERN_ALERT "Module %s unloaded.\n", MYMODNAME);
}

module_init(my_init_module);
module_exit(my_cleanup_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nilushan Silva");
MODULE_DESCRIPTION("task_struct offset Finder");
