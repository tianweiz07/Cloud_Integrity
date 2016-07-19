#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <inttypes.h>

#include <libvmi/libvmi.h>

int introspect_process_list (char *name);
