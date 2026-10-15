#include <stdint.h>

~>volatile uint32_t *const gpio_odr = (volatile uint32_t *)0x40020014;

void led_on(void)
{
    *gpio_odr |= 1u << 5;
}
