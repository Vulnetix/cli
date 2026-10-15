#include <stdlib.h>
#include <string.h>

void copy_name(char *buf, size_t n, const char *name)
{
~>    strlcpy(buf, name, n);
~>    char *slash = memrchr(buf, '/', strlen(buf));
~>    unsigned r = arc4random_uniform(10);
~>    qsort_r(buf, n, 1, cmp, NULL);
    (void)slash;
    (void)r;
}
