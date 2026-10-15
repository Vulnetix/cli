#include <stdint.h>
#include <stdlib.h>

uint32_t peek(const char *optarg, const char *buf) {
    unsigned long addr = strtoul(optarg, NULL, 0);
~>    int *target = (int *)addr;
    *target = 1;
    uintptr_t a = atoll(buf);
~>    return *(uint32_t *)a;
}
