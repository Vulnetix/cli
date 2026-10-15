#include <stdlib.h>
#include <string.h>

char *dup_token(const char *tok)
{
    char *out = malloc(strlen(tok) + 1);
~>    memcpy(out, tok, strlen(tok));
    return out;
}
