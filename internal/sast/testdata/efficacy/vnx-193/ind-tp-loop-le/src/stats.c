#include <string.h>

#define MAX_BUCKETS 32

static unsigned long histogram[MAX_BUCKETS];

void histogram_reset(void)
{
	int i;
~>	for (i = 0; i <= MAX_BUCKETS; i++)
		histogram[i] = 0;
}
