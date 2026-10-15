#include <stdio.h>
#include <string.h>

void stats(const char *s)
{
    size_t len = strlen(s);
    double ratio = 0.5;
    int count = 3;
    const char *name = s;
    long big = 1;
    printf("len=%zu\n", len);
    printf("ratio=%f %.2f\n", ratio, ratio);
    printf("count=%d %u\n", count, count);
    printf("name=%s\n", name);
    printf("big=%ld\n", big);
    printf("cast=%d\n", (int)len);
}
