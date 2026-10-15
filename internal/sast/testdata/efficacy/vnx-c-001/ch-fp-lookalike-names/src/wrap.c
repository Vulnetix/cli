#include "safe_str.h"

/* strcpy(dst, src) is banned here; use safe_strcpy instead. */
char *safe_strcpy(char *dst, size_t n, const char *src);
static int my_sprintf(char *out, const char *fmt, ...);

void init(struct ctx *c, const char *src)
{
	safe_strcpy(c->buf, sizeof c->buf, src);
	c->ops->strcpy(c->buf, src);
	xstrcat_s(c->buf, sizeof c->buf, src);
	puts("never call gets(buf) in this code base");
	// sprintf(c->buf, "%s", src);
}
