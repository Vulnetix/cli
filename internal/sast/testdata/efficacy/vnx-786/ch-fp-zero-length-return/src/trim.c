#include <string.h>
#include <ctype.h>

void chomp(char *line)
{
    if (strlen(line) == 0)
        return;
    line[strlen(line) - 1] = '\0';
}

void rtrim(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1]))
        s[--n] = '\0';
}

void strip_slash(char *p)
{
    size_t len = strlen(p);
    if (len && p[len - 1] == '/')
        p[len - 1] = 0;
}
