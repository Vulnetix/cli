#include <stdio.h>

void show(int pct, const char *s, int a, int b, int ok) {
    printf("%d%% done\n", pct);
    printf("a,b,c: %s\n", s);
    fprintf(stdout, "%d\n", max(a, b));
    printf("%s\n", ok ? "yes, really" : "no");
    printf("%-*.*s|\n", 10, 3, s);
    printf("%lld %zu %hhx %Lf\n", (long long)a, (size_t)b, (unsigned char)a, (long double)b);
    puts("printf(\"%d\") in a string is not a call");
    printf("done\n");
}
