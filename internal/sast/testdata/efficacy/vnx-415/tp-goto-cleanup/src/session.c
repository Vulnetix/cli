#include <stdlib.h>

int session_open(struct session *s, const char *user)
{
    char *name = strdup(user);
    char *token = NULL;
    int ret = -1;

    if (name == NULL)
        goto out;
    token = make_token(name);
    if (token == NULL) {
~>      free(name);
        goto out;
    }
    if (check_token(token) != 0) {
~>      free(token); goto out;
    }
    s->name = name;
    s->token = token;
    return 0;
out:
    free(token);
    free(name);
    return ret;
}
