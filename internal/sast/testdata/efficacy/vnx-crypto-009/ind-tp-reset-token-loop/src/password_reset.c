#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "user_store.h"

static const char alphabet[] =
    "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

int begin_password_reset(struct user_store *db, const char *email)
{
    char reset_token[33];
    size_t i;

    srand((unsigned) time(NULL));
    for (i = 0; i < sizeof(reset_token) - 1; i++) {
~>        reset_token[i] = alphabet[rand() % (sizeof(alphabet) - 1)];
    }
    reset_token[sizeof(reset_token) - 1] = '\0';

    return user_store_save_reset(db, email, reset_token);
}
