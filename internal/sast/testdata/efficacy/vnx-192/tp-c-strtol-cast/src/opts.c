#include <stdlib.h>

unsigned char parse_level(const char *s)
{
	long v = strtol(s, NULL, 10);
~>	return (unsigned char)v;
}
