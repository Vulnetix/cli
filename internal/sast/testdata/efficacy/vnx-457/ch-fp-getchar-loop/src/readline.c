#include <stdio.h>

int count_lines(FILE *fp)
{
    int c;
    int lines = 0;
    while ((c = getc(fp)) != EOF)
        if (c == '\n')
            lines++;
    return lines;
}
