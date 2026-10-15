#include <string.h>
#include <stddef.h>

#define HDR_LEN 4

int parse_packet(const unsigned char *pkt, size_t len, unsigned char *out)
{
	if (len < HDR_LEN)
		return -1;
	memcpy(out, pkt + HDR_LEN, len - HDR_LEN);
	return 0;
}

size_t body_len(size_t buflen, size_t hdr)
{
	size_t body = buflen > hdr ? buflen - hdr : 0;
	return body;
}

void tail(char *dst, const char *src, size_t total_size, size_t off)
{
	if (off <= total_size) {
		memmove(dst, src + off, total_size - off);
	}
}
