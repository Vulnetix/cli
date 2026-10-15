#include <stdlib.h>
#include <string.h>

void free_suffix(const char *name, const char *prefix)
{
~>    free((char *)name + strlen(prefix));
}

char *read_token(size_t len)
{
    char *tok = calloc(len + 1, 1);
    char *end;
    tok = tok + 2;
    end = tok + len;
    *end = '\0';
    if (tok[0] == '#') {
~>        free(tok);
        return NULL;
    }
    return tok;
}
