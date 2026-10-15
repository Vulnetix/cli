#include <stdlib.h>
#include <string.h>

char *join(const char *a, const char *b)
{
	size_t la = strlen(a);
	size_t lb = strlen(b);
	char *r = malloc(la + lb + 2);
	struct vec *v = malloc(sizeof(struct vec) * 16);
	v->cap = v->cap * 2;
	v->data = realloc(v->data, v->cap * sizeof(int));
	return r;
}
