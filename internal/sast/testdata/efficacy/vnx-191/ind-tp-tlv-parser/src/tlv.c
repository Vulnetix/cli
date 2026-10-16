#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define TLV_HDR 4

struct tlv {
	uint16_t type;
	uint8_t *value;
	size_t value_len;
};

int tlv_decode(const uint8_t *buf, size_t buf_len, struct tlv *out)
{
	out->type = (uint16_t)((buf[0] << 8) | buf[1]);
~>	out->value = malloc(buf_len - TLV_HDR);
	if (out->value == NULL)
		return -1;
~>	memcpy(out->value, buf + TLV_HDR, buf_len - TLV_HDR);
	out->value_len = buf_len - TLV_HDR;
	return 0;
}
