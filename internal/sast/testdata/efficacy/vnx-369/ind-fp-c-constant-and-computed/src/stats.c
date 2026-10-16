#include <stdlib.h>
#include <string.h>

double mean(const int *xs, size_t len)
{
	long sum = 0;
	size_t i;

	if (len == 0)
		return 0.0;
	for (i = 0; i < len; i++)
		sum += xs[i];
	return (double)sum / len;
}

int percent(int part)
{
	int whole = 200;
	return part * 100 / whole;
}

int parse_ratio(const char *arg)
{
	int d = atoi(arg);
	if (d == 0)
		return -1;
	return 100 / d;
}
