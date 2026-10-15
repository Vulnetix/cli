#include <stdint.h>

#define MASK 0xFFFF0000
#define REG_OFFSET 0x40

uint32_t read_reg(uint8_t *base)
{
    volatile uint32_t *r = (volatile uint32_t *)(base + 0x4000);
    uintptr_t addr = (uintptr_t)0x40020000;
    uint32_t v = (uint32_t)0x12345678;
    return *r + (uint32_t)addr + v;
}
