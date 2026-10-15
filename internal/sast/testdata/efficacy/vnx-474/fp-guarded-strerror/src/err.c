#include <string.h>

const char *error_text(int err, char *buf, size_t len)
{
#if defined(__GLIBC__) && defined(_GNU_SOURCE)
    return strerror_r(err, buf, len);
#else
    if (strerror_r(err, buf, len) != 0)
        return "unknown error";
    return buf;
#endif
}
