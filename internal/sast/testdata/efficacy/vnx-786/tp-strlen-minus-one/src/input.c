#include <stdio.h>
#include <string.h>

void read_line(char *line, int size)
{
    if (fgets(line, size, stdin) == NULL)
        return;
~>    line[strlen(line) - 1] = '\0';
}

void chomp(char *s)
{
    size_t len = strlen(s);
~>    if (s[len - 1] == '\n')
~>        s[len - 1] = 0;
}
