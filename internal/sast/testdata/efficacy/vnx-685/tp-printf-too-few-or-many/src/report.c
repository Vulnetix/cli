#include <stdio.h>
#include <syslog.h>

void report(const char *user, int code, FILE *log, char *buf, size_t n) {
~>    printf("user %s failed with %d\n", user);
~>    fprintf(log, "%s\n", user, code);
~>    snprintf(buf, n, "[%s] %*d", user, code);
~>    sprintf(buf, "%s:%s", user);
~>    syslog(LOG_ERR, "login failed for %s from %s", user);
~>    fprintf(stderr, "code=%d\n");
}
