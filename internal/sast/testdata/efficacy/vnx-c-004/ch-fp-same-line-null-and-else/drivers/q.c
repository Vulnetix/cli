#include <linux/slab.h>

void q_reset(struct q *q, int keep)
{
	free(q->buf); q->buf = NULL;
	if (q->tmp) free(q->tmp), q->tmp = NULL;
	if (!keep)
		kfree(q->name);
	else
		pr_info("%s\n", q->name);
	q->len = 0;
}
