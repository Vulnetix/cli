#include <stdio.h>
#include <string.h>

void read_line(char *buf, size_t size)
{
    size_t len;
    if (fgets(buf, size, stdin) == NULL)
        return;
    len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n')
        buf[len - 1] = '\0';
}

void chomp(char *line)
{
    size_t n = strlen(line);
    if (n == 0)
        return;
    line[n - 1] = 0;
}

void strip(char *s)
{
    if (*s && s[strlen(s) - 1] == '\n')
        s[strlen(s) - 1] = '\0';
    s[strcspn(s, "\n")] = '\0';
}
