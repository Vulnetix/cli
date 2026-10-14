#include <stdio.h>
#include <string.h>

int count_matches(const char *pattern)
{
    char cmd[256];
    char line[64];
    FILE *fp;

    strcpy(cmd, "grep -c ");
    strcat(cmd, pattern);
    strcat(cmd, " /var/log/app.log");
~>    fp = popen(cmd, "r");
    if (fp == NULL)
        return -1;
    fgets(line, sizeof(line), fp);
    pclose(fp);
    return atoi(line);
}

void list_dir(const char *dir)
{
    char *cmd = NULL;

    if (asprintf(&cmd, "ls -la '%s'", dir) < 0)
        return;
~>    FILE *p = popen(cmd,
                    "r");
    pclose(p);
    free(cmd);
}
