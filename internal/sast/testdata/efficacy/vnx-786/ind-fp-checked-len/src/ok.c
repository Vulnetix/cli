#include <string.h>

void chomp(char *s)
{
    size_t len = strlen(s);
    if (len > 0 && s[len - 1] == '\n')
        s[len - 1] = '\0';
}

void chomp2(char *s)
{
    if (s[0] == '\0')
        return;
    s[strlen(s) - 1] = '\0';
}
