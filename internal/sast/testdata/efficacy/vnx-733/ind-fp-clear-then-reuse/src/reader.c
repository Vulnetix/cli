#include <stdio.h>
#include <string.h>

int read_tokens(FILE *fp, int (*handle)(const char *))
{
    char token[64];
    int n = 0;
    for (;;) {
        memset(token, 0, sizeof(token));
        if (fgets(token, sizeof(token), fp) == NULL)
            break;
        n += handle(token);
    }
    return n;
}
