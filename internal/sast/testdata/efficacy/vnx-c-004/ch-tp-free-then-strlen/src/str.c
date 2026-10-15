#include <stdlib.h>
#include <string.h>
#include <stdio.h>

size_t trim_name(char *name)
{
	char *copy = strdup(name);
	free(copy);
~>	return strlen(copy);
}

void log_close(struct conn *c)
{
	free(c->peer);
	if (c->verbose)
~>		fprintf(stderr, "closed %s\n", c->peer);
}
