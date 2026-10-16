#include <stdio.h>
#include <syslog.h>

void report_failure(FILE *log, const char *user, int code)
{
~>    printf("user %s failed with %d\n", user);
~>    fprintf(log, "%s\n", user, code);
~>    syslog(LOG_WARNING, "auth failure for %s from %s", user);
}
