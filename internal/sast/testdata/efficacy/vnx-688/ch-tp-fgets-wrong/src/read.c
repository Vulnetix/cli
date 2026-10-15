#include <stdio.h>

void read_lines(FILE *fp)
{
    char buf[1024];
    char line[80];
~>    while (fgets(line, sizeof buf, fp) != NULL)
        puts(line);
    (void)buf;
}
