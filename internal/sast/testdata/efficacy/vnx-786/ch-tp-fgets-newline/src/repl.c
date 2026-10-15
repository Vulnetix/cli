#include <stdio.h>
#include <string.h>

int read_command(FILE *in, char *line, int cap)
{
    if (fgets(line, cap, in) == NULL)
        return -1;
~>    line[strlen(line)-1] = 0;
    return 0;
}
