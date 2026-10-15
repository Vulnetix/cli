#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *load_name(const char *src)
{
~>    char *buf = malloc(strlen(src) + 1);
    strcpy(buf, src);
    buf[0] = 'x';
    return buf;
}
