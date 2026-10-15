#include <stdlib.h>
#include <string.h>

#define RETURN_IF_NULL(p) do { if ((p) == NULL) return -1; } while (0)

int pool_init(char **slot, size_t n)
{
    char *mem = malloc(n);
    RETURN_IF_NULL(mem);
    memset(mem, 0, n);
    *slot = mem;
    return 0;
}
