#include <stdlib.h>
#include <string.h>

struct config { int port; };

static struct config g_config;

void get_config(struct config **out)
{
	*out = &g_config;
}

int get_buffer(char **out)
{
	static char scratch[64];
	*out = scratch;
	return 0;
}

int get_copy(char **out, const char *src)
{
	char tmp[32];
	strncpy(tmp, src, sizeof tmp - 1);
	tmp[sizeof tmp - 1] = '\0';
	*out = strdup(tmp);
	return 0;
}

void ctx_set(struct config *c, struct config *other)
{
	struct config *heap = malloc(sizeof *heap);
	c->port = other->port;
	free(heap);
}
