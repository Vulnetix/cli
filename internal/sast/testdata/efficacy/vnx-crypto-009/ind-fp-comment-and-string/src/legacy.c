#include <stdio.h>
#include <sodium.h>
#include "legacy.h"

/*
 * History: this used to do
 *     token[i] = alphabet[rand() % 62];
 * which was predictable. It now uses libsodium.
 */
void fill_token(unsigned char *token, size_t n)
{
    // session_id = rand();  -- removed in 2.4
    randombytes_buf(token, n);
    fprintf(stderr, "never use rand() for a session token\n");
}
