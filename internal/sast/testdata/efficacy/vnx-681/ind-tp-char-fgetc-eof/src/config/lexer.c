#include <stdio.h>

int count_lines(FILE *fp)
{
    int lines = 0;
    char c;
~>    while ((c = fgetc(fp)) != EOF) {
        if (c == '\n') {
            lines++;
        }
    }
    return lines;
}
