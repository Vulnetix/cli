#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "auth.h"
#include "tty.h"

int authenticate_user(const char *user)
{
    char *password = tty_read_password("Password: ");
    if (password == NULL) {
        fprintf(stderr, "could not read password\n");
        return -1;
    }

    int ok = check_credentials(user, password);
    audit_log(user, ok);
~>    free(password);
    return ok;
}

void release_login(struct login_req *req)
{
    if (!req)
        return;
    free(req->username);
~>    g_free(req->passphrase);
    free(req);
}
