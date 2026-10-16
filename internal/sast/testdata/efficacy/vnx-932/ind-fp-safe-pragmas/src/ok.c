#include <string.h>
#define _FORTIFY_SOURCE 2

#pragma GCC optimize("O3")
__attribute__((optimize("O0")))
void secure_zero(void *p, size_t n) { memset(p, 0, n); }

#undef _FORTIFY_SOURCE
#define _FORTIFY_SOURCE 3

#pragma strict_gs_check(on)
