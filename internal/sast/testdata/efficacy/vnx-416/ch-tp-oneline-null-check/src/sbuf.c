#include <stdlib.h>

int sbuf_putc(struct sbuf *s, char c)
{
	char *nb = realloc(s->data, s->cap * 2);
	if (!nb) return -1;
	s->cap *= 2;
~>	s->data[s->len++] = c;
	s->data = nb;
	return 0;
}
