#include <stdio.h>
#include <string.h>

void parse_headers(char *buf)
{
    char *line;
    for (line = strtok(buf, "\n"); line != NULL; line = strtok(NULL, "\n")) {
~>        char *name = strtok(line, ":");
        if (name != NULL) {
            printf("%s\n", name);
        }
    }
}
