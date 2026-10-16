#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

FILE *open_in(const char *dir, const char *file)
{
    char full[256] = "";
    char path[256];
    char line[128];
    strncat(full, file, sizeof(full) - strlen(full) - 1);
    strncpy(path, file, sizeof(path) - 1);
    char *copy = malloc(sizeof(line) + 1);
    mkdir(dir, 0755);
    chmod(path, S_IRUSR | S_IWUSR);
    FILE *a = fopen(full, "r+");
    FILE *b = fopen(full, "rb");
    FILE *c = fopen(full, "wbx");
    FILE *d = fopen(full, "a+e");
    fgets(line, sizeof(line), a);
    free(copy);
    (void)b; (void)c; (void)d;
    return a;
}
