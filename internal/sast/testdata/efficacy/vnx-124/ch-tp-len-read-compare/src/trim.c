#include <string.h>

void chomp(char *s)
{
    size_t n = strlen(s);
~>    s[n - 1] = '\0';
}
