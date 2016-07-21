#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <asm/uaccess.h>
#include <net/tcp.h>

#define MYMODNAME "FindProc "

static int my_init_module(void);
static void my_cleanup_module(void);

static int
my_init_module(void)
{
    unsigned long procnetoffset;
    unsigned long subdiroffset;
    unsigned long nameoffset;
    unsigned long nextoffset;
    unsigned long dataoffset;
    unsigned long showoffset;

    struct tcp_seq_afinfo *tcp_afinfo = NULL;

    printk(KERN_ALERT "Module %s loaded.\n\n", MYMODNAME);

    procnetoffset = (unsigned long)(&(init_net.proc_net)) - (unsigned long)(&(init_net));
    subdiroffset = (unsigned long)(&(init_net.proc_net->subdir)) - (unsigned long)(&(*(init_net.proc_net)));
    nameoffset = (unsigned long)(&(init_net.proc_net->name)) - (unsigned long)(&(*(init_net.proc_net)));
    nextoffset = (unsigned long)(&(init_net.proc_net->next)) - (unsigned long)(&(*(init_net.proc_net)));
    dataoffset = (unsigned long)(&(init_net.proc_net->data)) - (unsigned long)(&(*(init_net.proc_net)));

    tcp_afinfo = (struct tcp_seq_afinfo *) (init_net.proc_net->data);
    showoffset = (unsigned long)(&((tcp_afinfo->seq_ops.show))) - (unsigned long)(&(*tcp_afinfo));
 

    printk("procnetoffset = 0x%x\n", (unsigned int)procnetoffset);
    printk("subdiroffset = 0x%x\n", (unsigned int)subdiroffset);
    printk("nameoffset = 0x%x\n", (unsigned int)nameoffset);
    printk("nextoffset = 0x%x\n", (unsigned int)nextoffset);
    printk("dataoffset = 0x%x\n", (unsigned int)dataoffset);
    printk("showoffset = 0x%x\n", (unsigned int)showoffset);
 
    return 0;
}

static void my_cleanup_module(void)
{
    printk(KERN_ALERT "Module %s unloaded.\n", MYMODNAME);
}

module_init(my_init_module);
module_exit(my_cleanup_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tianwei Zhang");
MODULE_DESCRIPTION("proc file system offset Finder");
