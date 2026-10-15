#include <stdio.h>

/* Never use #pragma GCC optimize ("no-stack-protector") here. */
// __attribute__((no_stack_protector)) was removed in v2.
static const char *help = "build with -fno-stack-protector only for boot code";

void usage(void) {
    puts("do not #undef _FORTIFY_SOURCE");
}
