#include <string.h>

void chomp(char *line)
{
~>    line[strlen(line) - 1] = '\0';
}
