#include <stdio.h>
#include <string.h>

void greet(const char *who)
{
    char *p;
~>    strcpy(p, who);
    puts(p);
}

void read_line(FILE *in)
{
    char *line;
~>    fgets(line, 128, in);
}
