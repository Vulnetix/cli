#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define REC_HEADER 6

ssize_t read_record(int fd, const uint8_t *hdr, uint8_t *body)
{
	uint16_t rec_len = ntohs(*(const uint16_t *)(hdr + 2));
~>	size_t payload = rec_len - REC_HEADER;

	return read(fd, body, payload);
}

void forward_record(int sock, const uint8_t *frame, size_t frame_len)
{
~>	send(sock, frame + REC_HEADER, frame_len - REC_HEADER, 0);
}
