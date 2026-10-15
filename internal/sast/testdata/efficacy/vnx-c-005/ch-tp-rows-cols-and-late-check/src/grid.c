#include <stdlib.h>

char *make_grid(char **argv)
{
	int rows = atoi(argv[1]);
	int cols = atoi(argv[2]);
~>	char *grid = malloc(rows * cols);
	return grid;
}

char *body(const char *hdr)
{
	long len = strtol(hdr, NULL, 10);
~>	char *b = malloc(len + 1);
	if (len > 4096)
		return NULL;
	return b;
}
