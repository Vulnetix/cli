#include <stdio.h>
#include <string.h>

void log_line(char *line, const char *tag)
{
    size_t n;

    n = strlen(line);
    if (n > 0) {
        fprintf(stderr, "[%s] ", tag);
    }
~>    line[n] = ' ';
    fprintf(stderr, "%s\n", line);
}
