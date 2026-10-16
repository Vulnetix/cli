#include <stdlib.h>
#include <string.h>

int login(const char *user)
{
    char *password = malloc(128);
    if (!password)
        return -1;
    prompt_password(user, password, 128);
    int ok = verify(user, password);
~>    memset(password, 0, 128);
    free(password);
    return ok;
}
