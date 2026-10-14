#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

void banner(int argc, char **argv, const char *user)
{
    const char *fmt = getenv("BANNER_FORMAT");

    if (fmt == NULL)
        return;
~>    printf(fmt, user, argc);
~>    fprintf(stderr, argv[1], user);
~>    printf(getenv("GREETING"));
~>    fprintf(stderr, getenv("ERR_FORMAT"), user);
}

int handle(int sock, int id)
{
    char req[1024];
    char *out = NULL;
    ssize_t n;

    n = recv(sock, req, sizeof(req) - 1, 0);
    if (n <= 0)
        return -1;
    req[n] = '\0';
~>    if (asprintf(&out, req, id) < 0)
        return -1;
    send(sock, out, strlen(out), 0);
    free(out);
    return 0;
}

void vlog(const char *unused, va_list ap)
{
    const char *log_format = getenv("LOG_FORMAT");

~>    vfprintf(stderr, log_format, ap);
}
