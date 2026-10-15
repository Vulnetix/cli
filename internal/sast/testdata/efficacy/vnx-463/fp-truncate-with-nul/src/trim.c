#include <string.h>

void chomp(char *s)
{
    size_t n = strlen(s);
    if (n && s[n - 1] == '\n')
        s[n - 1] = '\0';
    s[strlen(s)] = '\0';
}
