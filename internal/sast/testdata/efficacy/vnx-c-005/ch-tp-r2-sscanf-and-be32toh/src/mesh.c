#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <endian.h>

struct vertex { float x, y, z; };

struct vertex *mesh_load(const char *hdr, const uint8_t *blob)
{
	unsigned nverts;
	if (sscanf(hdr, "verts %u", &nverts) != 1)
		return NULL;
~>	struct vertex *v = malloc(nverts * sizeof(struct vertex));
	uint32_t nidx = be32toh(*(const uint32_t *)blob);
~>	uint32_t *idx = malloc(sizeof(uint32_t) * nidx);
	(void)idx;
	return v;
}
