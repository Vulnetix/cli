#include <stdio.h>
#include <string.h>

void safe(char *dst, size_t n, const char *src, FILE *f)
{
    char line[128];
    fgets(line, sizeof line, stdin);
    strncpy(dst, src, n - 1);
    strlcpy(dst, src, n);
    strncat(dst, src, n - strlen(dst) - 1);
    snprintf(dst, n, "%s", src);
    vsnprintf(dst, n, "%s", ap);
    scanf("%15s", line);
    fscanf(f, "%d", &n);
    sscanf(src, "%d:%d", &a, &b);
    sprintf(dst, "%d", 42);
    sprintf(dst, "%.20s", src);
}
