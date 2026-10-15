#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

unsigned char *read_frame(const unsigned char *pkt)
{
	uint32_t len;
	memcpy(&len, pkt, 4);
	len = ntohl(len);
	size_t total = len + 16;
~>	unsigned char *buf = malloc(total);
	return buf;
}
