#include <stdlib.h>

#define RELEASE(p) do { free(p); free(p##_shadow); } while (0)
#define DROP(x) \
    free(x);    \
    free(x)

void doc(char *p)
{
    /* free(p); was called twice here once: free(p); */
    // free(p);
    puts("free(p); free(p);");
    free(p);
    // free(p);
    puts("call free(p) only once");
}
