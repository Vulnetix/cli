#include <stdio.h>
#include <stdlib.h>

int read_table(FILE *fp, struct entry **out)
{
	uint32_t count;
	if (fread(&count, sizeof count, 1, fp) != 1)
		return -1;
~>	*out = realloc(*out,
	               count * sizeof(struct entry));
	return *out ? 0 : -1;
}
