#include <stdlib.h>

int append_secret(struct keybuf *kb, const unsigned char *chunk, size_t n)
{
~>    unsigned char *grown = realloc(kb->secret, kb->len + n);
    if (grown == NULL)
        return -1;
    kb->secret = grown;
    return 0;
}

char *grow_password(char *pw_buf, size_t len)
{
~>    pw_buf = realloc(pw_buf,
                     len * 2);
    return pw_buf;
}
