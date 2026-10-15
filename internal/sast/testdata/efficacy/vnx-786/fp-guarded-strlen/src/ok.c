#include <string.h>

void chomp(char *s)
{
    size_t len = strlen(s);
    if (len > 0 && s[len - 1] == '\n')
        s[len - 1] = '\0';
}

void trim(char *line)
{
    if (strlen(line) > 0)
        line[strlen(line) - 1] = '\0';
}

void trim2(char *line)
{
    if (line[0] != '\0' && line[strlen(line) - 1] == '\n')
        line[strlen(line) - 1] = 0;
}

void trim3(char *s)
{
    size_t len = strlen(s);
    if (len == 0)
        return;
    s[len - 1] = 0;
}
