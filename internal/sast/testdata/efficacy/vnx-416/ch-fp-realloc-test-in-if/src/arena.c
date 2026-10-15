#include <stdio.h>
#include <stdlib.h>

int arena_grow(struct arena *a, size_t cap)
{
	unsigned char *nbase;

	if ((nbase = realloc(a->base, cap)) == NULL) {
		fprintf(stderr, "grow failed at %p\n", (void *)a->base);
		free(a->base);
		return -1;
	}
	a->base = nbase;
	a->cap = cap;
	return 0;
}

char *str_grow(char *s, size_t n)
{
	char *t;
	if (!(t = realloc(s, n))) {
		log_oom(s);
		return s;
	}
	return t;
}
