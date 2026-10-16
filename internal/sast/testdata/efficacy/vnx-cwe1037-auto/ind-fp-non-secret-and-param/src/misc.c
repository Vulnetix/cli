#include <stdlib.h>
#include <string.h>

void reset_ctx(struct ctx *c, char *password)
{
    char *scratch = malloc(256);
    use(scratch);
    memset(scratch, 0, 256);
    free(scratch);
    /* caller owns the password buffer */
    memset(password, 0, 64);
    memset(c->key, 0, sizeof c->key);
}
