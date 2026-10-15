#include <linux/fs.h>
#include <linux/uaccess.h>

struct demo_req { size_t len; char data[64]; };

static long demo_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct demo_req r;
	void __user *uarg = (void __user *)arg;

	if (copy_from_user(&r, uarg, sizeof(r)))
		return -EFAULT;
	return r.len;
}
