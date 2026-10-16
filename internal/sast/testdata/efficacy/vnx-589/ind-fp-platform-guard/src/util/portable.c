#include <string.h>
#include <strings.h>

int names_equal(const char *a, const char *b)
{
#ifdef _WIN32
    return _stricmp(a, b) == 0;
#else
    return strcasecmp(a, b) == 0;
#endif
}

void copy_name(char *dst, size_t n, const char *src)
{
#if defined(HAVE_STRLCPY)
    strlcpy(dst, src, n);
#else
    snprintf(dst, n, "%s", src);
#endif
}
