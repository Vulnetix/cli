#include <assert.h>

int check(int a, int b, int *out)
{
    int same = a == b;
    assert(a == b);
    if (a == b)
        return 1;
    *out = (a == b);
    return a == b ? 1 : 0;
}

int ok(int a, int b)
{
    return foo(a,
               b == 1);
}
