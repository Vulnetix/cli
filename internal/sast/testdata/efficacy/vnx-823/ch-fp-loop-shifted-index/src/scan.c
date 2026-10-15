#include <stddef.h>

#define N_ELEMENTS(a) (sizeof(a) / sizeof((a)[0]))

static int table[12];
static int other[13];

int sum_shifted(void)
{
	int s = 0;
	for (size_t i = 1; i <= N_ELEMENTS(table); i++)
		s += table[i - 1];
	for (size_t j = 0; j < N_ELEMENTS(table); j++)
		s += table[j];
	for (size_t k = 0; k <= N_ELEMENTS(table); k++)
		s += other[k];
	return s;
}
