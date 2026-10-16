#include <stdint.h>
#include "gpio.h"

~>#define GPIOA_ODR (*(volatile uint32_t *)0x40020014UL)

struct rcc_regs {
    volatile uint32_t cr;
    volatile uint32_t pllcfgr;
};

static volatile struct rcc_regs *rcc;

void gpio_init(void)
{
~>    rcc = (volatile struct rcc_regs *)0x40023800;
~>    volatile uint32_t *moder = (volatile uint32_t *) 0x40020000u;
    *moder |= 1u << 10;
    GPIOA_ODR |= 1u << 5;
}

static volatile uint32_t *systick_base(void)
{
~>    return (volatile uint32_t *)0xE000E010;
}
