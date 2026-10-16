#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

void safe(char *d, const char *s, const char *dir, FILE *in, const char *path)
{
    char line[128];
    strncat(d, s, sizeof(line) - strlen(d) - 1);
    strncpy(d, s, sizeof(line) - 1);
    fgets(line, sizeof(line), in);
    FILE *a = fopen(path, "r+");
    FILE *b = fopen(path, "rb");
    FILE *c = fopen(path, "wbx");
    FILE *e = fopen(path, "a+e");
    mkdir(dir, 0755);
    mkdir(dir, S_IRUSR | S_IWUSR | S_IXUSR);
    char *buf = malloc(sizeof(line) + 16);
}
