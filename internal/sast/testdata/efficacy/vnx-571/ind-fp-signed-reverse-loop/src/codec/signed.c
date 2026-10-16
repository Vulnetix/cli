#include <stdio.h>

struct pkt { int n; };

void dump(const int *v, int n, const struct pkt *p)
{
    for (int i = n - 1; i >= 0; i--) {
        printf("%d\n", v[i]);
    }
    if (p->n >= 0) {
        puts("ok");
    }
}
