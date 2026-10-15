#include <stdio.h>

int parse_line(const char *line, char *key, char *val)
{
~>	return sscanf(line, "%[^=]=%s", key, val);
}

int read_header(FILE *fp)
{
	char magic[8];
	char owner[32];
~>	if (fscanf(fp, "%7s %s", magic, owner) != 2)
		return -1;
	return 0;
}
