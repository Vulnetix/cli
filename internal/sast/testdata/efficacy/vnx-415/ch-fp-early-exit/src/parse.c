#include <stdlib.h>

int parse(const char *src)
{
	char *buf = strdup(src);
	if (!validate(buf)) {
		free(buf);
		return -1;
	}
	if (buf[0] == '#') {
		free(buf);
		exit(2);
	}
	consume(buf);
	free(buf);
	return 0;
}

void cleanup(struct a *x, struct a *y)
{
	free(x->name);
	free(y->name);
	if (x->owned) { free(x->data); return; }
	free(x->data);
}
