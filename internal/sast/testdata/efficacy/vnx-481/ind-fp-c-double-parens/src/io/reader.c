#include <stdio.h>
#include <stdlib.h>

int copy_stream(FILE *in, FILE *out)
{
    int c;
    char *buf;

    while ((c = getc(in)) != EOF)
        putc(c, out);
    if ((buf = malloc(16)))
        free(buf);
    if (c == EOF)
        return 0;
    return 1;
}
