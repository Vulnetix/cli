#include <stdlib.h>
#include <string.h>

unsigned char *frame_body(const unsigned char *buf, size_t buflen, size_t hdr)
{
~>	size_t body = buflen - hdr;
	unsigned char *out = malloc(body);
	if (!out)
		return NULL;
	memcpy(out, buf + hdr, body);
	return out;
}
