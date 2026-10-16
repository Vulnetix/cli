#include <stdio.h>
#include <stdlib.h>

char *read_line(FILE *fp)
{
    size_t cap = 64, len = 0;
    char *line = malloc(cap);
    int c;

    if (line == NULL)
        return NULL;
    while ((c = fgetc(fp)) != EOF && c != '\n') {
        if (len + 1 >= cap) {
            char *grown = realloc(line, cap * 2);
            if (grown == NULL) {
                free(line);
                return NULL;
            }
            cap *= 2;
~>            line[len++] = (char)c;
            continue;
        }
        line[len++] = (char)c;
    }
    line[len] = '\0';
    return line;
}
