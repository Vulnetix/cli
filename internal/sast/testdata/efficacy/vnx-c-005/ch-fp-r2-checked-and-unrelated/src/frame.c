#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#define MAX_FRAME 65536

uint8_t *frame_read(const uint8_t *hdr, const char *name)
{
	uint32_t len = ntohl(*(const uint32_t *)hdr);
	if (len == 0 || len > MAX_FRAME)
		return NULL;
	uint8_t *f = malloc(len + 4);
	char *label = malloc(strlen(name) + 1);
	free(label);
	return f;
}

int *table_new(const char *arg)
{
	size_t n = strtoul(arg, NULL, 10);
	return calloc(n, sizeof(int));
}
