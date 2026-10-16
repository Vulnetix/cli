#include <avr/io.h>
int main(void)
{
    DDRB = 0xFF;
~>    MCUCR &= ~(1 << JTD);
    for (;;) { }
}
