#include <ctype.h>
#include <stddef.h>

size_t skip_ws(const char *src, size_t pos)
{
	while (src[pos] && isspace((unsigned char)src[pos]))
		pos++;
	return pos;
}

void lower_in_place(char *s)
{
	for (char *p = s; *p; p++)
		*p = (char)tolower((unsigned char)*p);
}
