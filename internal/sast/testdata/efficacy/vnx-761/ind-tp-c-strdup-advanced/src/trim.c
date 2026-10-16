#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void show_trimmed(const char *in)
{
    char *line = strdup(in);
    if (!line)
        return;
    while (isspace((unsigned char)*line))
        line++;
    printf("%s\n", line);
~>    free(line);
}
