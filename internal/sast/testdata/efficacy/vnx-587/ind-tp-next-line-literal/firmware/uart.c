#include <stdint.h>

struct uart_regs {
    volatile uint32_t dr;
    volatile uint32_t fr;
};

static struct uart_regs *uart0;

void uart_setup(void)
{
~>    uart0 = (struct uart_regs *)
        0x4000C000;
    uart0->dr = 0;
}
