#include <string.h>

void first_upper(char *s, char *out)
{
    size_t len = strlen(s);
    out[0] = s[0] - 32;
    memcpy(out + 1, s + 1, len);
    out[len] = '\0';
}
