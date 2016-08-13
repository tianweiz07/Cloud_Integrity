#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/unistd.h>
#include <asm/cacheflush.h>
#include <linux/fs.h>
#include <asm/uaccess.h>        /* for put_user */
#include <linux/sched.h>

void **sys_call_table;

static uint64_t (*original_call)(void);

#define __NR_regdev 188


static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char *, size_t, loff_t *);

#define SUCCESS 0
#define DEVICE_NAME "chardev"   /* Dev name as it appears in /proc/devices   */
#define BUF_LEN 80              /* Max length of the message from the device */

static int Major;               /* Major number assigned to our device driver */
static int Device_Open = 0;     /* Is device open?
                                 * Used to prevent multiple access to device */
static char msg[BUF_LEN];       /* The msg the device will give when asked */
static char *msg_Ptr;


static struct file_operations fops = {
        .read = device_read,
        .write = device_write,
        .open = device_open,
        .release = device_release
};


asmlinkage int our_sys_open(const char* file, int flags, int mode) {
        Major = register_chrdev(0, DEVICE_NAME, &fops);

        if (Major < 0) {
          printk(KERN_ALERT "Registering char device failed with %d\n", Major);
          return Major;
        }

        printk(KERN_INFO "I was assigned major number %d. To talk to\n", Major);
        printk(KERN_INFO "the driver, create a dev file with\n");
        printk(KERN_INFO "'mknod /dev/%s c %d 0'.\n", DEVICE_NAME, Major);
        printk(KERN_INFO "Try various minor numbers. Try to cat and echo to\n");
        printk(KERN_INFO "the device file.\n");
        printk(KERN_INFO "Remove the device file and module when done.\n");

        return SUCCESS;
}

static int device_open(struct inode *inode, struct file *file)
{
        static int counter = 0;

        if (Device_Open)
                return -EBUSY;

        Device_Open++;
        sprintf(msg, "I already told you %d times Hello world!\n", counter++);
        msg_Ptr = msg;
        try_module_get(THIS_MODULE);

        return SUCCESS;
}

static int device_release(struct inode *inode, struct file *file)
{
        Device_Open--;          /* We're now ready for our next caller */

        module_put(THIS_MODULE);

        return 0;
}

static ssize_t device_read(struct file *filp,   /* see include/linux/fs.h   */
                           char *buffer,        /* buffer to fill with data */
                           size_t length,       /* length of the buffer     */
                           loff_t * offset)
{
        int bytes_read = 0;

        if (*msg_Ptr == 0)
                return 0;
        while (length && *msg_Ptr) {
                put_user(*(msg_Ptr++), buffer++);
                length--;
                bytes_read++;
        }
        return bytes_read;
}

static ssize_t
device_write(struct file *filp, const char *buff, size_t len, loff_t * off)
{
        printk(KERN_ALERT "Sorry, this operation isn't supported.\n");
        return -EINVAL;
}


void set_addr_rw(unsigned long addr) {

    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);

    if (pte->pte &~ _PAGE_RW) pte->pte |= _PAGE_RW;

}

void set_addr_ro(unsigned long addr) {

    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);

    pte->pte = pte->pte &~_PAGE_RW;

}

int __init init_hooking(void) {
    sys_call_table = (void*)0xffffffff81600300;
    original_call = (uint64_t(*)(void))(sys_call_table[__NR_regdev]);

    set_addr_rw((unsigned long)sys_call_table);
    sys_call_table[__NR_regdev] = our_sys_open;

    return 0;
}

void __exit exit_hooking(void)
{
    sys_call_table[__NR_regdev] = original_call;
    set_addr_ro((unsigned long)sys_call_table);

    unregister_chrdev(Major, DEVICE_NAME);

    return;
}

module_init(init_hooking);
module_exit(exit_hooking);

MODULE_LICENSE("GPL");
