#include <stdint.h>

void dma_kick(volatile uint8_t *base)
{
    *(volatile uint32_t *)(base + 0x1000) = 1;
    *(uint32_t *)base = 0;
    *p = (int)0x40000000;
}
