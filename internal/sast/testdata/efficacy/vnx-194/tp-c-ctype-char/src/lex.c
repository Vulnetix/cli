#include <ctype.h>

const char *skip_ws(const char *p)
{
~>	while (isspace(*p))
		p++;
	return p;
}

int count_digits(const char *s)
{
	int n = 0;
	char c;
	while ((c = *s++) != '\0') {
~>		if (isdigit(c))
			n++;
	}
	return n;
}
