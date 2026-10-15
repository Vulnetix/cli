#include <linux/fs.h>
#include <linux/uaccess.h>

struct demo_req { int op; int value; };

static long demo_ioctl(struct file *filp,
                       unsigned int cmd,
                       unsigned long arg)
{
~>    struct demo_req *r = (struct demo_req *)arg;

    switch (cmd) {
    case 1:
        r->value = 42;
        return 0;
    default:
        return -ENOTTY;
    }
}
