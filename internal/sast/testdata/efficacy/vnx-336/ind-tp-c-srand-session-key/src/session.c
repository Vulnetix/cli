#include <stdio.h>
#include <stdlib.h>

#define KEY_LEN 32

void generate_session_key(char *out, size_t outlen)
{
    static const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    size_t i;

~>    srand(1234);
    for (i = 0; i < KEY_LEN && i + 1 < outlen; i++) {
        out[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    out[i] = '\0';
}
