#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <net/tcp.h>


#define MYMODNAME "FindSocket "

static int my_init_module(void);
static void my_cleanup_module(void);

static int my_init_module(void) {

    unsigned long portOffset;
    unsigned long addrOffset;

    unsigned long hlistOffset1;
    unsigned long hlistOffset2;

    struct sock *sk;
    struct inet_sock *inet;

    printk(KERN_ALERT "Module %s loaded.\n\n", MYMODNAME);

    sk = kmalloc(sizeof(struct sock), GFP_KERNEL);
    inet = inet_sk(sk);

    portOffset = (unsigned long) (&(inet->inet_dport)) - (unsigned long) (sk);
    addrOffset = (unsigned long) (&(inet->inet_daddr)) - (unsigned long) (sk);

    hlistOffset1 = (unsigned long) (&(tcp_hashinfo.listening_hash[0])) - (unsigned long)(&(tcp_hashinfo));
    hlistOffset2 = (unsigned long) (&(tcp_hashinfo.listening_hash[1])) - (unsigned long)(&(tcp_hashinfo.listening_hash[0]));

    printk("portOffset = 0x%x\n", (unsigned int)portOffset);
    printk("addrOffset = 0x%x\n", (unsigned int)addrOffset);

    printk("hlistOffset1 = 0x%x\n", (unsigned int)hlistOffset1);
    printk("hlistOffset2 = 0x%x\n", (unsigned int)hlistOffset2);

    return 0;
}

static void my_cleanup_module(void){
    printk(KERN_ALERT "Module %s unloaded.\n", MYMODNAME);
}

module_init(my_init_module);
module_exit(my_cleanup_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tianwei Zhang");
MODULE_DESCRIPTION("struct sock and inet_sock offset Finder");
