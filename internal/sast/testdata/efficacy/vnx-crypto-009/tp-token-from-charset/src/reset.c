#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789";

/* Builds the password-reset link mailed to the user. */
void issue_reset_link(char *out, size_t n)
{
    char token[33];
    srand((unsigned) time(NULL));
    for (size_t i = 0; i < 32; i++)
~>        token[i] = alphabet[rand() % (sizeof(alphabet) - 1)];
    token[32] = '\0';
    snprintf(out, n, "https://example.com/reset?t=%s", token);
}

void fill_iv(unsigned char iv[16])
{
    for (int i = 0; i < 16; i++) {
~>        iv[i] = (unsigned char) (rand() & 0xff);
    }
}
