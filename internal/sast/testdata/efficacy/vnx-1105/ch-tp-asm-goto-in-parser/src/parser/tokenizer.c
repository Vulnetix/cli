#include <stddef.h>
#include "tokenizer.h"

static int likely_overflow(size_t a, size_t b)
{
~>    asm goto("add %1, %0\n\tjc %l[overflow]"
             : "+r"(a)
             : "r"(b)
             :
             : overflow);
    return 0;
overflow:
    return 1;
}

size_t tokenize(const char *src, size_t len, struct token *out)
{
    size_t n = 0;
~>    __asm__ ("" ::: "memory");
    for (size_t i = 0; i < len; i++) {
        if (likely_overflow(n, 1))
            break;
        n++;
    }
    return n;
}
