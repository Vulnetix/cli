#include <stdlib.h>

void obj_close(struct obj *o)
{
	free(o);
~>	if (o->flags & 1)
		notify();
}

void obj_destroy(struct obj *s)
{
	free(s);
~>	free(s->name);
}
