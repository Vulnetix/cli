#include <unistd.h>
#include <arpa/inet.h>

ssize_t read_payload(int fd, char *buf, unsigned int len, unsigned int consumed)
{
~>	len -= consumed;
	return read(fd, buf, len);
}

ssize_t read_framed(int fd, const unsigned char *raw, char *out)
{
	uint16_t n = ntohs(*(const uint16_t *)raw);
~>	size_t body = n - 2;
	return read(fd, out, body);
}
