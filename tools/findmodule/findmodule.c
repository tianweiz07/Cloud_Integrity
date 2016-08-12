#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>

#define MYMODNAME "FindModule "

static int my_init_module(void);
static void my_cleanup_module(void);

static int my_init_module(void) {
    struct module *mod;
    unsigned long nameOffset;
    unsigned long addrOffset;
    unsigned long sizeOffset;

    printk(KERN_ALERT "Module %s loaded.\n\n", MYMODNAME);
    mod = &__this_module;

    if (mod != NULL) {
        nameOffset = (unsigned long) (&(mod->name)) - (unsigned long) (&(mod->list));
        addrOffset = (unsigned long) (&(mod->module_core)) - (unsigned long) (&(mod->list));
        sizeOffset = (unsigned long) (&(mod->core_size)) - (unsigned long) (&(mod->list));

        printk(KERN_ALERT "name = 0x%x;\n", (unsigned int) nameOffset);
        printk(KERN_ALERT "module_core = 0x%x;\n", (unsigned int) addrOffset);
        printk(KERN_ALERT "core_size = 0x%x;\n",(unsigned int) sizeOffset);
    }
    else {
        printk(KERN_ALERT "%s: found no module to populate module structure.\n", MYMODNAME);
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
MODULE_DESCRIPTION("module structure offset Finder");
