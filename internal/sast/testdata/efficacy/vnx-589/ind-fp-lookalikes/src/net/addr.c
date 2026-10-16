#include <stdio.h>
#include <string.h>

struct str_ops {
    size_t (*strlcpy)(char *, const char *, size_t);
};

extern size_t my_strlcpy(char *dst, const char *src, size_t n);

void fill(char *dst, size_t n, const char *src, const struct str_ops *ops)
{
    my_strlcpy(dst, src, n);
    ops->strlcpy(dst, src, n);
    /* strlcpy(dst, src, n) is not on glibc before 2.38 */
    const char *msg = "use strlcpy() only with a fallback";
    snprintf(dst, n, "%s", msg);
}
