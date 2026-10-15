#include <stdint.h>

void clock_init(void)
{
~>    *(volatile uint32_t *)0x40021018 |= (1u << 2);
~>    *((volatile uint32_t *) 0x40010800) = 0x44444444u;
~>    uint32_t v = *(volatile uint32_t *)0x40021000;
    (void)v;
}
