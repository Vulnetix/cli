#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

FILE *open_in(const char *dir, const char *file)
{
    char full[256] = "";
    char path[256];
    char line[128];
    strcpy(full, dir);
~>    strncat(full, file, sizeof(full));
~>    strncpy(path, file, strlen(file));
~>    mkdir(dir, 755);
~>    FILE *fp = fopen(full, "rw");
    if (fp) {
~>        fgets(line, sizeof(line) + 1, fp);
    }
    return fp;
}
