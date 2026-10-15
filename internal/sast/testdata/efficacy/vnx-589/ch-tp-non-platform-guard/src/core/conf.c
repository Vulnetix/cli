#include <string.h>
#include <stdio.h>

#ifndef CONF_H_INCLUDED
#define CONF_H_INCLUDED
#endif

void dump(char *dst, size_t n, const char *src)
{
#ifdef DEBUG
    fprintf(stderr, "%s\n", src);
#endif
~>    strcpy_s(dst, n, src);
~>    char *s = strchrnul(dst, ':');
    (void)s;
}
