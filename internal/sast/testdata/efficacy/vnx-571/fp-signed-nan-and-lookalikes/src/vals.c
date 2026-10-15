#include <stddef.h>
#include <sys/types.h>

struct node { int n; struct node *next; };

int scan(struct node *p, double x, size_t cap, int lo, int hi)
{
    ssize_t got = (ssize_t)cap - 1;
    int count = 0;
    if (x != x)
        return -1;
    if (got >= 0 && count >= 0)
        return 0;
    if ((int)cap >= 0)
        return 0;
    if (p->n >= 0 && p->next == p->next->next)
        return 1;
    if (lo != 1 || hi != 2)
        return 2;
    if (lo > 10 || lo < 5)
        return 3;
    if (lo < 0 || lo > 100)
        return 4;
    return lo == hi;
}

int other(void)
{
    size_t len = 4;
    int len2 = (int)len;
    long n = len2 - 8;
    for (n = len2; n >= 0; n--)
        len2--;
    return len2;
}
