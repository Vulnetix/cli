#include <stdlib.h>

int vec_reserve(struct vec *v, size_t cap)
{
	int *ni = realloc(v->items, cap * sizeof(*ni));
	if (ni == NULL) { free(v->items); v->items = NULL; return -1; }
	v->items = ni;
	v->items[0] = 0;
	v->cap = cap;
	return 0;
}

char *dup_grow(char *s, size_t n)
{
	char *t = realloc(s, n);
	if (!t) return s;
	t[n - 1] = '\0';
	return t;
}
