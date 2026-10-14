#include <stdarg.h>
#include <stdio.h>

void audit_login(const char *user, const char *host)
{
    char msg[64];

~>    sprintf(msg, "login user=%s host=%s", user, host);
    write_audit(msg);
}

void audit_path(const char *dir, const char *file)
{
    char path[128];
~>    sprintf(path,
            "%s/%-12s.log", dir, file);
    open_log(path);
}

void logf(const char *fmt, ...)
{
    char buf[256];
    va_list ap;

    va_start(ap, fmt);
~>    vsprintf(buf, fmt, ap);
    va_end(ap);
    emit(buf);
}
