#include <stdio.h>
#include <string.h>

int count_matches(const char *pattern, const char *logfile)
{
    char cmd[512];
    FILE *fp;
    int count = 0;

    strcpy(cmd, "grep -c '");
    strcat(cmd, pattern);
    strcat(cmd, "' ");
    strcat(cmd, logfile);
~>    fp = popen(cmd, "r");
    if (fp == NULL)
        return -1;
    if (fscanf(fp, "%d", &count) != 1)
        count = -1;
    pclose(fp);
    return count;
}
