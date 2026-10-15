#include <stddef.h>
#include <string.h>

void reverse_print(const int *v, size_t n)
{
~>    for (size_t i = n - 1; i >= 0; i--) {
        printf("%d\n", v[i]);
    }
}

int check(const char *s, unsigned int idx)
{
~>    if (strlen(s) >= 0 && idx >= 0)
        return 1;
~>    if (0 <= sizeof(s))
        return 2;
    return 0;
}
