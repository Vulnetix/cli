#include <stdio.h>

void report(const char *msg)
{
~>	fprintf(stderr, msg);
}

void show(char *line)
{
~>	printf(line);
}
