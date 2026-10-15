#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int read_config(char *line, int size)
{
    FILE *fp = fopen("/etc/app.conf", "r");

~>    fgets(line, size, fp);
    fclose(fp);
    return 0;
}

void home_path(char *dst)
{
    const char *home = getenv("HOME");
~>    strcpy(dst, home);
    strcat(dst, "/.apprc");
}
