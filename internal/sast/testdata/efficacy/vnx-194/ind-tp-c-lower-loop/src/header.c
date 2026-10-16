#include <ctype.h>
#include <string.h>

void normalize_header_name(char *name)
{
	char *p;
	for (p = name; *p; p++) {
~>		*p = tolower(*p);
	}
}

int header_is_numeric(const char *value)
{
	char c;
	while ((c = *value++) != '\0') {
~>		if (!isdigit(c))
			return 0;
	}
	return 1;
}
