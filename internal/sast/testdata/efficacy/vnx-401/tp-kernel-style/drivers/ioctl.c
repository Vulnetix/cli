static long dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct req *r = kzalloc(sizeof(*r), GFP_KERNEL);

	if (!r)
		return -ENOMEM;
	if (copy_from_user(&r->hdr, (void __user *)arg, sizeof(r->hdr)))
~>		return -EFAULT;
	if (r->hdr.len > MAX_LEN) {
		kfree(r);
		return -EINVAL;
	}
	return submit(r);
}
