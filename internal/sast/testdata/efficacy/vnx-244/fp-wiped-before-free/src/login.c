#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>

int check_login(const char *user)
{
    char *password = read_password_from_tty();
    int ok = verify(user, password);
    explicit_bzero(password, strlen(password));
    free(password);
    return ok;
}

void drop_key(struct ctx *c)
{
    OPENSSL_cleanse(c->session_key, c->key_len);
    free(c->session_key);
    sodium_memzero(c->secret, sizeof c->secret);
    sodium_free(c->secret);
}
