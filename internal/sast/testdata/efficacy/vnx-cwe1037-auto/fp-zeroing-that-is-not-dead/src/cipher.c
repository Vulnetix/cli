#include <stdlib.h>
#include <string.h>

#include "cipher.h"

/* Initialising a buffer before it is filled is not a dead store. */
int load_key(struct ctx *c, const char *path)
{
    unsigned char key[32];

    memset(key, 0, sizeof key);
    if (read_key(path, key, sizeof key) != 0)
        return -1;
    memcpy(c->key, key, sizeof key);
    return 0;
}

/* The caller owns c: the store survives the return. */
void clear_ctx_key(struct ctx *c)
{
    memset(c->key, 0, sizeof c->key);
}

void reset_token(struct ctx *c)
{
    memset(c->token, 0, sizeof c->token);
    return;
}

/* Not key material. */
void drop_buffer(char *buf, size_t n)
{
    memset(buf, 0, n);
    free(buf);
}

void fill_pattern(unsigned char *secret, size_t n)
{
    memset(secret, 0xA5, n);
    free(secret);
}

void log_it(void)
{
    puts("memset(password, 0, n); free(password);");
    /* memset(password, 0, n);
       free(password); */
}
