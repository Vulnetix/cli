#include <stdio.h>

#define TRACE(x) do { if (0) printf("%d\n", x); } while (0)

void dump(int v)
{
#if 0
    printf("disabled %d\n", v);
#endif
    if (0) {
        printf("never\n");
    }
    if (v < 0) {
        printf("negative\n");
    }
    TRACE(v);
}
