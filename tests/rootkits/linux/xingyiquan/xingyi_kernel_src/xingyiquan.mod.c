#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x59101cf6, "module_layout" },
	{ 0xf5d6b4d, "kmalloc_caches" },
	{ 0x5a34a45c, "__kmalloc" },
	{ 0xff984224, "call_usermodehelper_setfns" },
	{ 0x4c4fef19, "kernel_stack" },
	{ 0xffa0373b, "call_usermodehelper_exec" },
	{ 0xd20bd7f3, "vfs_readdir" },
	{ 0x25ec1b28, "strlen" },
	{ 0x17175757, "commit_creds" },
	{ 0x4aabc7c4, "__tracepoint_kmalloc" },
	{ 0x82529367, "seq_printf" },
	{ 0xdce1ce59, "remove_proc_entry" },
	{ 0x152202be, "filp_close" },
	{ 0xce7e465, "nf_register_hook" },
	{ 0xd4079e5b, "kobject_del" },
	{ 0xf4a0b4c3, "sock_i_ino" },
	{ 0x3c2c5af5, "sprintf" },
	{ 0x7d11c268, "jiffies" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x4f8b5ddb, "_copy_to_user" },
	{ 0xb8e7ce2c, "__put_user_8" },
	{ 0x480bd6bb, "kmem_cache_alloc_notrace" },
	{ 0x11089ac7, "_ctype" },
	{ 0xd92efe9f, "current_task" },
	{ 0x94d32a88, "__tracepoint_module_get" },
	{ 0x7ec9bfbc, "strncpy" },
	{ 0xb4390f9a, "mcount" },
	{ 0xc3aaf0a9, "__put_user_1" },
	{ 0x1e6d26a8, "strstr" },
	{ 0x8bdb80fa, "init_net" },
	{ 0xdb5d7816, "fput" },
	{ 0x1b6c897b, "prepare_creds" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x8cce1ba3, "call_usermodehelper_setup" },
	{ 0xca3f8758, "nf_unregister_hook" },
	{ 0x37a0cba, "kfree" },
	{ 0x97b62d29, "fget" },
	{ 0x5a4896a8, "__put_user_2" },
	{ 0x9f100139, "jiffies_to_clock_t" },
	{ 0x9edbecae, "snprintf" },
	{ 0xa3a5be95, "memmove" },
	{ 0x4f6b400b, "_copy_from_user" },
	{ 0xe3034683, "sock_i_uid" },
	{ 0xc1e89689, "filp_open" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "0BF3D037BFB3B0B64930B0B");
