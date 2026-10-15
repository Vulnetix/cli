#include <string.h>
#include <stdlib.h>

int login(const char *user) {
    char *password = malloc(128);
    int ok = verify(user, password);
    explicit_bzero(password, 128);
    free(password);
    char buffer[64];
    memset(buffer, 0, sizeof(buffer));
    return ok;
}
