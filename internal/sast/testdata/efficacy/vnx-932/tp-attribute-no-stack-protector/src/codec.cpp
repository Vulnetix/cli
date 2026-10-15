#include <cstring>

~>__attribute__((no_stack_protector)) void decode(const char *in, char *buf) {
    std::strcpy(buf, in);
}

~>static void __attribute__ ((optimize("no-stack-protector"))) fast_copy(char *d, const char *s) {
    while ((*d++ = *s++)) {}
}

~>[[gnu::no_stack_protector]] int scan(char *line);
