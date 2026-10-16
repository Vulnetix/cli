#include <linux/slab.h>
#include <linux/printk.h>

struct acme_req {
    u32 id;
    void *buf;
};

static void acme_complete(struct acme_req *req)
{
    kfree(req->buf);
    kfree(req);
~>    pr_debug("acme: completed request %u\n", req->id);
}
