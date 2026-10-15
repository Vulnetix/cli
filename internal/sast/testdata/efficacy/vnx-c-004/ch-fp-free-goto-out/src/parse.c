#include <stdlib.h>

int parse(const char *s, struct out *o)
{
	char *tmp = strdup(s);
	if (!tmp)
		return -1;
	if (tmp[0] == '#') {
		free(tmp);
		goto fail;
	}
	o->first = tmp[0];
	free(tmp);
	return 0;
fail:
	o->first = 0;
	return -1;
}
