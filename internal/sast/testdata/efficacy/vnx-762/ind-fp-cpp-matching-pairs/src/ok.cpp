#include <cstdlib>
#include <memory>
#include <new>

struct Widget { int a; };

void pairs(size_t n)
{
    char *a = new char[n];
    delete[] a;
    char *b = (char *)malloc(n);
    free(b);
    Widget *w = new Widget;
    delete w;
    std::unique_ptr<char[]> c(new char[n]);
    std::unique_ptr<Widget> d(new Widget);
}

void placement(void *mem)
{
    Widget *w = new (mem) Widget;
    w->~Widget();
}
