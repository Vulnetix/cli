#ifndef PERIPH_H
#define PERIPH_H

typedef struct { unsigned int CR; unsigned int SR; } UART_TypeDef;

~>#define UART1 ((UART_TypeDef *) 0x40011000UL)
~>#define VGA_TEXT ((unsigned short *)0xB8000)

#endif
