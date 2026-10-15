#include <openssl/crypto.h>
#include <stdlib.h>

int derive_from_prompt(unsigned char *out, size_t outlen)
{
    char *passwd = read_tty_line("Passphrase: ");
    int rc = run_pbkdf2(passwd, out, outlen);
~>    OPENSSL_free(passwd);
    return rc;
}
