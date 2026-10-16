#include <stdio.h>
#include <string.h>
#include "xalloc.h"

void build(const char *s)
{
    char *p = xmalloc(64);
    strcpy(p, s);
    /* char *q = malloc(8); strcpy(q, s); */
    const char *doc = "buf = malloc(n); strcpy(buf, x);";
    puts(doc);
}
