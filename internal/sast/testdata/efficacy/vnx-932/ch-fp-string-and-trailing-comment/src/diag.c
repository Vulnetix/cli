#include <stdio.h>

static const char *flags = "-fno-stack-protector -U_FORTIFY_SOURCE";

void report(void) {
    printf("attribute __attribute__((no_stack_protector)) is not allowed\n");
    puts("[[gnu::no_stack_protector]] and __declspec(safebuffers) are banned");
}

int value = 1; /* __attribute__((no_stack_protector)) removed */
int other = 2; // #pragma strict_gs_check(off) was here
