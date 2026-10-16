#include <stdio.h>

int dump_state(const char *service, const char *payload)
{
    char path[256];
    FILE *fp;

    snprintf(path, sizeof(path), "/tmp/%s.state", service);
~>    fp = fopen(path, "a");
    if (!fp)
        return -1;
    fprintf(fp, "%s\n", payload);
    fclose(fp);
    return 0;
}

void crash_log(const char *msg)
{
~>    FILE *log = fopen("/var/tmp/crash.log", "w+");
    if (log) {
        fputs(msg, log);
        fclose(log);
    }
}
