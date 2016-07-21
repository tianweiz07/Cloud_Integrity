#include <stdlib.h>
#include <stdio.h>
#include <time.h>

int main () {
    struct timespec res;
    res.tv_sec = 10;
    res.tv_nsec = 0;
    printf("Using clock_nanosleep to sleep 10 seconds...\n");
    clock_nanosleep(CLOCK_REALTIME, 0, &res, NULL);

    printf("Using nanosleep to sleep 10 seconds...\n");
    nanosleep(&res, NULL);
    return 0;
}
