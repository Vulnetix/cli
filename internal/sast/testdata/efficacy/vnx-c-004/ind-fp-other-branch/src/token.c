#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void token_release(char *tok, int keep, size_t *out_size)
{
    if (!keep) {
        free(tok);
    } else {
        printf("keeping token %s\n", tok);
    }
}

void token_drop(char *tok)
{
    free(tok);
    if (tok) {
        fputs("dropped\n", stderr);
    }
}
