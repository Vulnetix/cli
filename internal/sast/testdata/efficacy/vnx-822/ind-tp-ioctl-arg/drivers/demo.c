#include <linux/fs.h>
struct demo_req { int a; };
static long demo_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
~>	struct demo_req *r = (struct demo_req *)arg;
	return r->a;
}
