#include <string.h>
#define HDR 8

void body(char *out, const char *in, size_t n)
{
    if (n > HDR) memcpy(out, in + HDR, n - HDR);
}
