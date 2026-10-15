#include <stdio.h>
#include <string.h>

int parse(const char *s, int *out, double *ratio) {
    size_t n = strlen(s);
    printf("%d\n", (int)strlen(s));
    printf("%u\n", (unsigned)sizeof(n));
    printf("%zu %zu\n", sizeof(n), strlen(s));
    printf("%lu\n", sizeof n);
    printf("%s\n", s + 1);
    sscanf(s, "%d", out);
    sscanf(s, "%lf", ratio);
    return 0;
}
