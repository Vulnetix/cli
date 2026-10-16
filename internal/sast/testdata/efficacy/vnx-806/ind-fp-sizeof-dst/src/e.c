#include <string.h>
struct T { int x; };
void f(const char *src, const char *raw)
{
    char dst[32];
    struct T x;
    strncpy(dst, src, sizeof(dst) - 1);
    memcpy(&x, raw, sizeof(x));
}
