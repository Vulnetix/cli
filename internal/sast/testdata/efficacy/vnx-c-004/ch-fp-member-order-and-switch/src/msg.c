#include <stdlib.h>

void msg_free(struct msg *m)
{
	free(m->body);
	free(m->hdr);
	free(m);
}

int handle(struct msg *m, int kind)
{
	switch (kind) {
	case 1:
		free(m->body);
		break;
	case 2:
		return m->body[0];
	}
	return 0;
}

void each(struct item **items, int n)
{
	for (int i = 0; i < n; i++) {
		if (!items[i]->live) {
			free(items[i]);
			continue;
		}
		items[i]->age++;
	}
}
