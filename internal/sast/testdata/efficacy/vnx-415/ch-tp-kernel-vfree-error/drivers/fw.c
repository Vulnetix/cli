#include <linux/vmalloc.h>

static int fw_upload(struct device *dev, const u8 *data, size_t len)
{
	u8 *fw_buf;
	int ret;

	fw_buf = vmalloc(len);
	if (!fw_buf)
		return -ENOMEM;
	memcpy(fw_buf, data, len);
	ret = fw_send(dev, fw_buf, len);
	if (ret < 0) {
		dev_err(dev, "upload failed: %d\n", ret);
		vfree(fw_buf);
	}
	fw_log(dev, ret);
~>	vfree(fw_buf);
	return ret;
}
