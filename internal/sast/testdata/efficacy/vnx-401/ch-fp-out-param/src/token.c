#include <stdlib.h>

int next_token(struct lexer *lx, char **out)
{
    char *tok = malloc(lx->max);
    if (!tok)
        return -1;
    *out = tok;
    if (lx->pos >= lx->len)
        return 1;
    copy_token(lx, tok);
    return 0;
}
