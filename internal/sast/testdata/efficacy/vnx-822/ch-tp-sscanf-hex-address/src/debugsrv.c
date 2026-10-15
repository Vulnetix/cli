#include <stdio.h>
#include <stdint.h>
#include <string.h>

void handle_peek(const char *cmdline, char *reply, size_t cap)
{
    unsigned long addr;
    if (sscanf(cmdline, "peek %lx", &addr) != 1)
        return;
~>    uint32_t value = *(volatile uint32_t *)addr;
    snprintf(reply, cap, "%08x", value);
}

void handle_poke(const char *cmdline)
{
    uintptr_t where = 0;
    unsigned int val = 0;
    sscanf(cmdline, "poke %" SCNxPTR " %x", &where, &val);
~>    *(unsigned int *)where = val;
}
