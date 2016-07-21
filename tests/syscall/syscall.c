/* execve.c */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <signal.h>

int main(int argc, char *argv[])
{
    printf("pid = %d\n", getpid());
    printf("getpid = %d\n", SYS_getpid);
    printf("getpgid = %d\n", SYS_getpgid);
    pid_t pid, pgid;
    while (1) {
        pid = syscall(SYS_getpid, NULL, NULL);
        pgid = syscall(SYS_getpgid, pid, NULL);
        syscall(SYS_chmod, "/home/tianwez/aaa", 0444);
    }
    return 0;
}
