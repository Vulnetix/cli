#include <stdint.h>

~>#define UART0_DR (*(volatile unsigned int *)0x4000C000)
~>#define GPIOA_BASE ((volatile uint32_t *)0x40020000UL)

void init(void)
{
~>    int *p = (int *)0x8000;
~>    volatile uint32_t *rcc = (volatile uint32_t*) 0x40023830;
    uint8_t *reg;
~>    reg = (uint8_t *)0xFFFF0000u;
    *p = 1;
    *rcc |= 1;
    *reg = 0;
}
