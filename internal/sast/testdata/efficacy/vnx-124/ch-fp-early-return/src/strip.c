#include <string.h>

void strip(char *s)
{
    size_t len = strlen(s);
    if (len == 0)
        return;
    s[len - 1] = '\0';
}
