#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *read_two(FILE *fp, size_t n)
{
	char *buf = malloc(n);
	if (!buf)
		return NULL;
	fgets(buf, (int)n, fp);
	consume(buf);
	free(buf);
	buf =
	    calloc(1, n * 2);
	if (!buf)
		return NULL;
	fgets(buf, (int)n * 2, fp);
	consume(buf);
	free(buf);
	char *tmp = strdup("x");
	free(tmp);
	if (refill(&tmp) < 0)
		return NULL;
	free(tmp);
	return NULL;
}
