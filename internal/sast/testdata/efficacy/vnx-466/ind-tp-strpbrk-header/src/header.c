#include <string.h>

char *header_value(char *line)
{
    char *delim = strpbrk(line, ":;");
~>    return delim + 1;
}
