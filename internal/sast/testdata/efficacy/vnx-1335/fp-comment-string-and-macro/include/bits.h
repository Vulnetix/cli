#ifndef BITS_H
#define BITS_H

/* 1 << 40 overflows int; always write 1ULL << 40 */
// (uint32_t)v >> 32 is undefined
#define BIT(n) (1ULL << (n))
#define HIGH BIT(40)

static const char *why = "1 << 40 is undefined behaviour";

#endif
