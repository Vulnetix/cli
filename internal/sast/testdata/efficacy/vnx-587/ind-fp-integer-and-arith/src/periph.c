#include <stdint.h>

extern uintptr_t periph_base;

uint32_t *regs_for(unsigned int idx)
{
    uintptr_t addr = (uintptr_t)0x40020000;
    uint32_t raw = (uint32_t)0x40020000;
    uint32_t *r = (uint32_t *)(periph_base + 0x4000);
    if ((void *)r == (void *)0x40020000) {
        return 0;
    }
    write_reg((volatile uint32_t *)0x40021000, idx);
    (void)addr;
    (void)raw;
    /* uart = (struct uart *)0x4000C000; */
    const char *msg = "p = (int *)0x8000;";
    (void)msg;
    return r;
}
