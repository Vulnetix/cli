#include <stdlib.h>
#include <string.h>

int check_login(const char *user)
{
    char *password = read_password_from_tty();
    int ok = verify(user, password);
~>    free(password);
    return ok;
}

void drop_session(struct session *s)
{
    send_logout(s);
~>    free(s->session_key);
~>    free( s->passphrase );
    free(s);
}
