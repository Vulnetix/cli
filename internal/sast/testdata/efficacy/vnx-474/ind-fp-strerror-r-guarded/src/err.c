#include <string.h>

const char *describe(int err, char *buf, size_t n)
{
#if (_POSIX_C_SOURCE >= 200112L) && !defined(_GNU_SOURCE)
    if (strerror_r(err, buf, n) != 0)
        return "unknown error";
    return buf;
#else
    return strerror_r(err, buf, n);
#endif
}
