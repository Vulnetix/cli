#include <stdio.h>
#include <string.h>

void read_line(FILE *fp, char *line, int size)
{
    fgets(line, size, fp);
~>    line[ strlen(line) - 1 ] = '\0';
}
