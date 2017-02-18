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

    unsigned long dportOffset;
    unsigned long daddrOffset;
    unsigned long sportOffset;

    unsigned long hlistOffset;
    unsigned long hlistLength;

    unsigned long firstOffset;
    unsigned long nextOffset;

    struct sock *sk;
    struct inet_sock *inet;

    struct hlist_nulls_node *node;

    printk(KERN_ALERT "Module %s loaded.\n\n", MYMODNAME);

    sk = kmalloc(sizeof(struct sock), GFP_KERNEL);
    inet = inet_sk(sk);

    dportOffset = (unsigned long) (&(inet->inet_dport)) - (unsigned long) (sk);
    daddrOffset = (unsigned long) (&(inet->inet_daddr)) - (unsigned long) (sk);
    sportOffset = (unsigned long) (&(inet->inet_sport)) - (unsigned long) (sk);

    hlistOffset = (unsigned long) (&(tcp_hashinfo.listening_hash[0])) - (unsigned long)(&(tcp_hashinfo));
    hlistLength = (unsigned long)sizeof(struct inet_listen_hashbucket);


    firstOffset = (unsigned long) (&(tcp_hashinfo.listening_hash[0].head.first)) - (unsigned long) (&(tcp_hashinfo.listening_hash[0]));

    node = tcp_hashinfo.listening_hash[0].head.first;

    nextOffset = (unsigned long) (&(node->next)) - (unsigned long)(&(*node));

    printk("dportOffset = 0x%x\n", (unsigned int)dportOffset);
    printk("daddrOffset = 0x%x\n", (unsigned int)daddrOffset);
    printk("sportOffset = 0x%x\n", (unsigned int)sportOffset);

    printk("hlistOffset = 0x%x\n", (unsigned int)hlistOffset);
    printk("hlistLength = 0x%x\n", (unsigned int)hlistLength);
    printk("firstOffset = 0x%x\n", (unsigned int)firstOffset);
    printk("nextOffset = 0x%x\n", (unsigned int)nextOffset);

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
