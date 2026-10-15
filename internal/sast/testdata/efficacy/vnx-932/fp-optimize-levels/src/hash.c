#include <stddef.h>

#pragma GCC optimize ("O2")
#pragma GCC optimize("-O3")
#pragma GCC push_options
#define _FORTIFY_SOURCE 2
#define _FORTIFY_SOURCE 3
#pragma strict_gs_check(on)
__attribute__((optimize("O0"))) void secure_zero(void *p, size_t n) {
    volatile unsigned char *v = p;
    while (n--) *v++ = 0;
}
__attribute__((stack_protect)) int guarded(void);

#ifdef _FORTIFY_SOURCE
#undef _FORTIFY_SOURCE
#endif
#define _FORTIFY_SOURCE 2
