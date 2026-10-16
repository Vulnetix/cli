#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

void build(char *full, char *path, const char *file, const char *dir)
{
    char line[128];
    FILE *in = NULL;
~>    strncat(full, file, sizeof(full));
~>    strncpy(path, file, strlen(file));
~>    fgets(line, sizeof(line) + 1, in);
~>    FILE *fp = fopen(path, "rw");
~>    mkdir(dir, 755);
}
