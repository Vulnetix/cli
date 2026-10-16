#include <cstddef>

~>__attribute__((no_stack_protector))
void fast_copy(char *dst, const char *src, size_t n) {
    for (size_t i = 0; i < n; i++) dst[i] = src[i];
}

~>[[gnu::no_stack_protector]] void other(char *p) { p[0] = 0; }
