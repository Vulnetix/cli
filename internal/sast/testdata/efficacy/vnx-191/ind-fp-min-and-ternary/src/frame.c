#include <stddef.h>
#include <string.h>

#define HDR 8
#define MIN(a, b) ((a) < (b) ? (a) : (b))

size_t frame_body(const char *frame, size_t len, char *out, size_t out_len)
{
	size_t body = len > HDR ? len - HDR : 0;
	memcpy(out, frame + HDR, MIN(body, out_len));
	return body;
}
