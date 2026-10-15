#include <stddef.h>

int max_of(const int *v, size_t n)
{
    int best;
    size_t i;
    best = v[0];
    for (i = 1; i < n; i++) {
        if (v[i] > best)
            best = v[i];
    }
    int flag;
    if (n > 3)
        flag = 1;
    else
        flag = 0;
    return best + flag;
}
