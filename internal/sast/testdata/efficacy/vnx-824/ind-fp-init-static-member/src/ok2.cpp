#include <cstring>

static char *g_cache;
extern int *shared;

struct holder {
    char *buf;
    void fill() { std::strcpy(buf, "a"); }
};

void f(const char *src)
{
    char *p = nullptr;
    char *q = new char[16];
    static char *sp;
    std::strcpy(q, src);
    if (p == nullptr) p = q;
    sp[0] = 'x';
    g_cache[0] = 'y';
    // char *z; strcpy(z, src);
    const char *msg = "char *z; z->x = 1;";
    (void)msg;
}
