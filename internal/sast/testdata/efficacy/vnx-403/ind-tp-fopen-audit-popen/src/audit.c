#include <stdio.h>
#include <time.h>

static FILE *audit;

int audit_init(const char *path)
{
~>    audit = fopen(path, "a");
    return audit ? 0 : -1;
}

void audit_event(const char *who, const char *what)
{
    if (!audit)
        return;
    fprintf(audit, "%ld %s %s\n", (long)time(NULL), who, what);
    fflush(audit);
}

int audit_rotate_compress(const char *old_path)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "gzip -9 '%s'", old_path);
    FILE *p = popen(cmd, "r");
    if (!p)
        return -1;
    return pclose(p);
}
