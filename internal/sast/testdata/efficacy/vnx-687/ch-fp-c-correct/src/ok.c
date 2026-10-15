#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

void ok(char *dst, size_t cap, const char *src, const char *p)
{
    char path[128] = "/tmp/";
    strncat(path, src, sizeof(path) - strlen(path) - 1);
    strncpy(dst, src, cap - 1);
    chmod(p, 0755);
    chmod(p, S_IRUSR | S_IWUSR);
    FILE *f = fopen(p, "rb+");
    FILE *g = fopen(p, "wx");
    fclose(f); fclose(g);
}
