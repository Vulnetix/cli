#include <stdio.h>
#include <string.h>

void read_line(FILE *fp, char *line, int size)
{
    if (fgets(line, size, fp) == NULL)
        return;
    line[strcspn(line, "\n")] = '\0';
}
