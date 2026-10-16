#include <stdlib.h>
#include <string.h>

char *token_dup(const char *tok)
{
    size_t len = strlen(tok);
    char *copy = malloc(len + 1);
    if (copy == NULL)
        return NULL;
~>    memcpy(copy, tok, len);
    return copy;
}

void header_set(char *out, const char *name)
{
~>    memcpy(out, name, strlen(name));
    puts(out);
}
