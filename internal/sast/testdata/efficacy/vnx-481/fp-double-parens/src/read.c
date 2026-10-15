#include <stdio.h>
#include <stdlib.h>

int copy(FILE *in, FILE *out)
{
    int c;
    char *p;
    while ((c = getc(in)) != EOF)
        putc(c, out);
    if ((p = malloc(16)))
        free(p);
    if ((p = getenv("HOME")) == NULL)
        return -1;
    return 0;
}

int tokens(char *p, char *q)
{
    while (p = q, q = next_token(q, ','), p) {
        use(p);
    }
    return 0;
}
