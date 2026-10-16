#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define TLV_HDR 4

int tlv_decode(const uint8_t *buf, size_t buf_len, uint8_t **value)
{
	if (buf_len < TLV_HDR)
		return -1;

	*value = malloc(buf_len - TLV_HDR);
	if (*value == NULL)
		return -1;
	memcpy(*value, buf + TLV_HDR, buf_len - TLV_HDR);
	return 0;
}
