##
## Makefile for ** MALICIOUS CODE: PROJECT - DEADLANDS **
## 
## Made by majdi
## Login   <majdi.toumi@gmail.com>
## 
##

# module name
NAME		=	hookIDT
KERNEL_RELEASE	=	`uname -r`

# sources
SRC		=	hookIDT.c

# objects
OBJ		=	$(SRC:.c=.o)

# initializations
obj-m		:=	$(NAME).o

# rules:
default		:
			@ echo "\033[33m[MODULE COMPILATION]:\033[0m"
			make -C /usr/src/linux-headers-$(KERNEL_RELEASE)  M=`pwd` modules

clean		:
			@ echo "\033[33m[MODULE CLEAN FILES]:\033[0m"
			make -C /usr/src/linux-headers-$(KERNEL_RELEASE) M=`pwd` clean

.PHONY		:	default clean
