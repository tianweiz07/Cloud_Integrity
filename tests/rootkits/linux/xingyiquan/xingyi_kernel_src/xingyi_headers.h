#ifndef _xingyi_headers_H_
#define _xingyi_headers_H_

#include <linux/module.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/version.h>
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33))
	#include <generated/autoconf.h>
#else
	#include <linux/autoconf.h>
#endif
#include <net/tcp.h>
#include <linux/in.h>
#include <linux/vmalloc.h>
#include <linux/idr.h>
#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/proc_fs.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29))
	#include <linux/cred.h>
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0))
	#include <linux/uidgid.h>
#endif
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/netfilter_ipv4.h>
#include <linux/random.h>
#endif
