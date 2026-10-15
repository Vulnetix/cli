#include <stdint.h>
#include <string.h>

struct hdr {
	uint16_t type;
	uint16_t len;
};

size_t pack(unsigned char *out, const struct hdr *h, const void *body, size_t n)
{
	unsigned char *cursor = out;
	memcpy(cursor, h, sizeof(*h));
	cursor = cursor + sizeof(*h);
	memcpy(cursor, body, n);
	const uint8_t *payload = (const uint8_t *)h + sizeof(struct hdr);
	(void)payload;
	struct hdr *next = (struct hdr *)(out + sizeof(struct hdr) + n);
	(void)next;
	return n + sizeof(*h);
}
