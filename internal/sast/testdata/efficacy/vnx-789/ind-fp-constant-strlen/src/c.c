#include <stdlib.h>
#include <string.h>

char *dup_it(const char *s)
{
    char *a = malloc(256);
    char *b = malloc(strlen(s) + 1);
    char *c = calloc(16, sizeof(int));
    strcpy(b, s);
    free(a); free(c);
    return b;
}
