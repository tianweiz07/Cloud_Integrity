#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>

#define MYMODNAME "FindTaskStruct "

static int my_init_module(void);
static void my_cleanup_module(void);

static int my_init_module(void) {
    struct task_struct *p = NULL;
    unsigned long commOffset;
    unsigned long tasksOffset;
    unsigned long mmOffset;
    unsigned long pidOffset;
    unsigned long pgdOffset;
    unsigned long addrOffset;

    printk(KERN_ALERT "Module %s loaded.\n\n", MYMODNAME);
    p = current;

    if (p != NULL) {
        commOffset = (unsigned long) (&(p->comm)) - (unsigned long) (p);
        tasksOffset = (unsigned long) (&(p->tasks)) - (unsigned long) (p);
        mmOffset = (unsigned long) (&(p->mm)) - (unsigned long) (p);
        pidOffset = (unsigned long) (&(p->pid)) - (unsigned long) (p);
        pgdOffset = (unsigned long) (&(p->mm->pgd)) - (unsigned long) (p->mm);
        addrOffset = (unsigned long) (&(p->mm->start_code)) - (unsigned long) (p->mm);

        printk(KERN_ALERT "linux_name = 0x%x;\n", (unsigned int) commOffset);
        printk(KERN_ALERT "linux_tasks = 0x%x;\n",(unsigned int) tasksOffset);
        printk(KERN_ALERT "linux_mm = 0x%x;\n", (unsigned int) mmOffset);
        printk(KERN_ALERT "linux_pid = 0x%x;\n", (unsigned int) pidOffset);
        printk(KERN_ALERT "linux_pgd = 0x%x;\n", (unsigned int) pgdOffset);
    }
    else {
        printk(KERN_ALERT "%s: found no process to populate task_struct.\n", MYMODNAME);
    }

    return 0;
}

static void my_cleanup_module(void) {
    printk(KERN_ALERT "Module %s unloaded.\n", MYMODNAME);
}

module_init(my_init_module);
module_exit(my_cleanup_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tianwei Zhang");
MODULE_DESCRIPTION("task_struct offset Finder");
