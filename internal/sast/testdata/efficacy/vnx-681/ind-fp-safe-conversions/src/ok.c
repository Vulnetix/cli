#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

void show(const char *s)
{
    int len = strlen(s);
    printf("%.*s\n", (int)strlen(s), s);
    size_t n = strlen(s);
    off_t pos = ftello(stdin);
    uint32_t w = strlen(s);
    long end = ftell(stdin);
    uint64_t big = strlen(s);
    (void)len; (void)n; (void)pos; (void)w; (void)end; (void)big;
}
