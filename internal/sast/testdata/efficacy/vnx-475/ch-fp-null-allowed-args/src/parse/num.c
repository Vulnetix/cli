#include <stdio.h>
#include <stdlib.h>
#include <string.h>

long parse(const char *s, char *line)
{
    long v = strtol(s, NULL, 10);
    char *tok = strtok(line, ",");
    while (tok) {
        tok = strtok(NULL, ",");
    }
    setbuf(stdout, NULL);
    fflush(NULL);
    double d = strtod(s, NULL);
    return v + (long)d;
}
