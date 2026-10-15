#include <linux/slab.h>

static int widget_probe(struct widget *dev)
{
	int ret;

	dev->buf = kzalloc(64, GFP_KERNEL);
	if (!dev->buf)
		return -ENOMEM;
	ret = widget_init(dev);
	if (ret) {
~>		kfree(dev->buf);
		goto err_free;
	}
	return 0;

err_free:
	kfree(dev->buf);
	return ret;
}

void ctx_drop(struct ctx *ctx)
{
	free((void *)ctx->name);
	ctx->refs--;
~>	free(ctx->name);
}
