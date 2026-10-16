#include <linux/fs.h>
#include <linux/uaccess.h>
struct demo_req { int a; };
static long demo_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct demo_req req;
	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	return req.a;
}
