#include <stdio.h>
#include <string.h>

struct session {
    char user[64];
    char host[128];
    int port;
};

void log_login(const struct session *s)
{
    char msg[96];
~>    sprintf(msg,
            "login user=%s host=%s port=%d",
            s->user, s->host, s->port);
    puts(msg);
}

int format_line(char *out, const char *fmt, va_list ap)
{
~>    return vsprintf(out, fmt, ap);
}
