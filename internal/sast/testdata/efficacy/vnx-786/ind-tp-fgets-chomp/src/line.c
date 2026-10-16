#include <stdio.h>
#include <string.h>

int read_cmd(FILE *in, char *line, size_t n)
{
    if (fgets(line, n, in) == NULL)
        return -1;
~>    line[strlen(line) - 1] = '\0';
    return 0;
}
