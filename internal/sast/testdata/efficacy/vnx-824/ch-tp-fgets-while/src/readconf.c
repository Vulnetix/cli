#include <stdio.h>
#include <string.h>

int count_lines(FILE *fp)
{
    int n = 0;
    char *line;

~>    while (fgets(line, 256, fp) != NULL) {
        n++;
    }
    return n;
}

void set_port(void)
{
	struct config *cfg;
	int unused = 0;
~>	cfg->port = 8080;
	(void)unused;
}
