#ifndef TOKEN_H
#define TOKEN_H
#include <string.h>

static inline char *next_token(char *s)
{
    char *sep = strpbrk(s, " \t,");
~>    return &sep[1];
}

#endif
