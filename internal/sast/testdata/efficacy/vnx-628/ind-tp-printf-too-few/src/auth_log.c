#include <stdio.h>
#include <syslog.h>

void log_failure(FILE *out, const char *user, int code, const char *addr)
{
~>    printf("user %s failed with %d\n", user);
~>    fprintf(out, "%s: login failure from %s (code %d)\n", user, addr);
~>    syslog(LOG_WARNING, "auth failure for %s from %s", user);
    fprintf(out, "%s: %d from %s\n", user, code, addr);
}

void log_extra(const char *user, int code)
{
~>    printf("user %s\n", user, code);
}
