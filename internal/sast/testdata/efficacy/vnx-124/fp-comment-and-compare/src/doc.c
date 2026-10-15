#include <string.h>

/* buf[strlen(buf) - 1] = '\0' underwrites when buf is empty. */
// target[len] = 0;  after readlink without checking -1
int ends_nl(const char *s)
{
    size_t n = strlen(s);
    return n > 0 && s[n - 1] == '\n';
}
