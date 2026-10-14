#include <stdio.h>

#ifndef HAVE_ALLOCA
char *alloca ();
void *alloca(size_t size);
#endif
#define alloca(n) __builtin_alloca(n)
#define STACK_ARRAY(type, name, count) type *name = alloca(sizeof(type) * (count))

/* Avoid alloca(len) on untrusted lengths. */
void explain(void)
{
    // char *p = alloca(len);
    puts("alloca(len) is not used here");
}
