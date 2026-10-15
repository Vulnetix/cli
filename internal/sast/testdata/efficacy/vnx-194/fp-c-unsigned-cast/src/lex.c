#include <ctype.h>

const char *skip_ws(const char *p)
{
	while (isspace((unsigned char)*p))
		p++;
	return p;
}

int count_upper(const unsigned char *s)
{
	int n = 0;
	unsigned char c;
	while ((c = *s++) != 0) {
		if (isupper(c))
			n++;
	}
	return n;
}
