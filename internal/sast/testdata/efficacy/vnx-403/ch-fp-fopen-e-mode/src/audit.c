#include <stdio.h>
#include <stdlib.h>

static FILE *audit;

void audit_init(const char *path)
{
    audit = fopen(path, "ae");
}

void audit_notify(const char *msg)
{
    FILE *p = popen("/usr/sbin/sendmail admin", "w");
    fputs(msg, p);
    pclose(p);
}
