#include <stdlib.h>

void set_sep(char *line, const char *opt)
{
    int sep = atoi(opt);
~>    line[5] = sep;
    puts(line);
}
