#include <string.h>
#include <stdlib.h>

int login(const char *user) {
    char *password = malloc(128);
    if (!read_password(password, 128)) {
        return -1;
    }
    int ok = verify(user, password);
~>    memset(password, 0, 128);
    free(password);
    return ok;
}
