#include <stdlib.h>
#include <string.h>

char *copy_name(const char *name)
{
~>	char *out = malloc(strlen(name));
	if (out == NULL)
		return NULL;
	strcpy(out, name);
	return out;
}

char *join(const char *a, const char *b)
{
	char *r;
~>	r = (char *)malloc(strlen(a) + strlen(b));
	strcpy(r, a);
	strcat(r, b);
	return r;
}
