#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

#define __NR_regdev 188

int main(int argc, char* argv[]) {
	syscall(__NR_regdev);
	return 0;
}
