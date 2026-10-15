#include <stdint.h>

~>static void __attribute__((noinline, no_stack_protector)) early_init(uint8_t *stack) {
    stack[0] = 0;
}

~>__attribute__((optimize("O2", "no-stack-protector")))
int checksum(const uint8_t *p, int n) {
    int s = 0;
    while (n--) s += *p++;
    return s;
}

~>__attribute__ ((used, __no_stack_protector__)) void trampoline(void);
