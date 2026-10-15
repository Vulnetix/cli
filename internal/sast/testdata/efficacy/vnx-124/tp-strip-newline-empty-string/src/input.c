#include <stdio.h>
#include <string.h>

void read_line(char *buf, size_t size)
{
    if (fgets(buf, size, stdin) == NULL)
        return;
~>    buf[strlen(buf) - 1] = '\0';
}

void chomp(char *line)
{
    if (line[strlen(line)-1] == '\n')
~>        line[strlen(line)-1] = 0;
}
