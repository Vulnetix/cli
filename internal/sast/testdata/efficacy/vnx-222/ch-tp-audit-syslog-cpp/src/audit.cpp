#include <cstdio>
#include <syslog.h>

void audit_login_failure(const char *user, const char *host, const char *reason)
{
    char msg[80];
~>    std::snprintf(msg, sizeof msg, "login failed user=%s host=%s reason=%s", user, host, reason);
    syslog(LOG_AUTHPRIV | LOG_WARNING, "%s", msg);
}
