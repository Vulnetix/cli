#include <stdio.h>

struct ctx {
	const char *label;
	int *counter;
};

void ctx_init(struct ctx *c, int id)
{
	char label[16];
	int counter = 0;
	snprintf(label, sizeof label, "c%d", id);
~>	c->label = label;
~>	c->counter = &counter;
}
