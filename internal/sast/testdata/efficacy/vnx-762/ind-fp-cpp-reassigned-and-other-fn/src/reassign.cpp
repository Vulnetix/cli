#include <cstdlib>

void reassigned(size_t n)
{
    char *p = new char[n];
    delete[] p;
    p = (char *)malloc(n);
    free(p);
}

char *make(size_t n)
{
    char *buf = new char[n];
    return buf;
}

void drop(char *buf)
{
    delete[] buf;
}

int renew = 0;
void renewal(int newfree)
{
    renew = newfree;
}
