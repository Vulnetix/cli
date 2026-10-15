#include <stdlib.h>
#include <string.h>

int check_login(const char *user) {
    char *password = malloc(128);
    if (!password)
        return -1;
    read_password(password, 128);
    int ok = verify(user, password);
~>    memset(password, 0, 128);
    free(password);
    return ok;
}

void drop_ctx(struct session *s) {
~>    memset(s->session_key, 0, sizeof(s->session_key));
    free(s->session_key);
    free(s);
}
