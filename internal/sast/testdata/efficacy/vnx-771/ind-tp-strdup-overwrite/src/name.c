#include <string.h>
#include <stdio.h>

void pick(const char *a, const char *b)
{
~>    char *s = strdup(a);
    if (strlen(b) > strlen(a)) {
        s = strdup(b);
    }
    printf("%zu\n", strlen(s));
}
