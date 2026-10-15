#include <linux/fs.h>

struct demo_req { size_t len; char data[64]; };

static long demo_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
~>	struct demo_req *r = (struct demo_req *)arg;

	if (cmd == DEMO_SET)
		return r->len;
	return 0;
}
