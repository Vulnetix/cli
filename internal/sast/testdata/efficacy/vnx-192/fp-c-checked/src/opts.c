#include <stdlib.h>
#include <limits.h>

/* short count = atoi(argv[1]); would truncate */
unsigned char parse_level(const char *s)
{
	long v = strtol(s, NULL, 10);
	if (v < 0 || v > UCHAR_MAX)
		return 0;
	return (unsigned char)v;
}

long parse_long(const char *s)
{
	long n = strtol(s, NULL, 10);
	int i = atoi(s);
	long long ll = strtoll(s, NULL, 10);
	return n + i + ll;
}
