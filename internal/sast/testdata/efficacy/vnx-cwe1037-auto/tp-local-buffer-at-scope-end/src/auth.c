#include <string.h>

#include "auth.h"

int check_password(const char *input)
{
    char password[128];
    int ok;

    if (read_stored_password(password, sizeof password) < 0)
        return -1;
    ok = strcmp(input, password) == 0;
~>    memset(password, 0, sizeof(password));
    return ok;
}

void derive_and_use(const char *pin)
{
    unsigned char derived_key[32];

    pbkdf2(pin, derived_key, sizeof derived_key);
    unlock_store(derived_key);
~>    memset(derived_key, 0x00, sizeof derived_key);
}
