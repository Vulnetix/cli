#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_JOBS 64

static void do_job(int i) { printf("job %d\n", i); }

int run_jobs(int argc, char **argv)
{
    if (argc < 2)
        return 1;

    int jobs = atoi(argv[1]);
    if (jobs < 0 || jobs > MAX_JOBS) {
        fprintf(stderr, "jobs must be 0..%d\n", MAX_JOBS);
        return 1;
    }
    for (int i = 0; i < jobs; i++) {
        do_job(i);
    }

    const char *name = argv[0];
    for (size_t i = 0; i < strlen(name); i++) {
        putchar(name[i]);
    }
    return 0;
}

int parse_records(const uint8_t *buf, size_t len)
{
    uint16_t remaining;
    memcpy(&remaining, buf, sizeof(remaining));
    remaining = ntohs(remaining);
    while (remaining-- > 0) {
        if (len < 4)
            return -1;
        buf += 4;
        len -= 4;
    }
    return 0;
}
