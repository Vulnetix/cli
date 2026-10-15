#include <string.h>

/* OpenSSL pem_password_cb: the buffer is length-delimited by the return value. */
static int password_cb(char *buf, int size, int rwflag, void *userdata)
{
    const char *pass = userdata;
    size_t pass_len;

    if (pass == NULL)
        return -1;
    pass_len = strlen(pass);
    if (pass_len > (size_t)size)
        return -1;
    memcpy(buf, pass, pass_len);
    return (int)pass_len;
}

void set_token(struct blob *b, const char *tok)
{
    size_t n = strlen(tok);
    memcpy(b->data, tok, n);
    b->length = n;
}
