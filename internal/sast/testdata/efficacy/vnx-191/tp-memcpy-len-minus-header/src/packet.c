#include <string.h>
#include <stdint.h>

#define HDR_LEN 4

int parse_packet(const uint8_t *pkt, size_t len, uint8_t *out)
{
	uint16_t type = (uint16_t)(pkt[0] << 8 | pkt[1]);
~>	memcpy(out, pkt + HDR_LEN, len - HDR_LEN);
	return type;
}

void copy_tail(char *dst, const char *src, size_t total_size, size_t off)
{
~>	memmove(dst,
		src + off,
		total_size - off);
}
