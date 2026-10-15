#include <stdio.h>
#include <syslog.h>

void report(const char *prog, int code, const char *msg) {
~>    fprintf(stderr, "%s: exited with %d\n", prog);
~>    syslog(LOG_ERR, "failed: %s (%d)", msg);
~>    printf("%d %d\n", code, code, code);
    fprintf(stderr, "%s: exited with %d\n", prog, code);
}
