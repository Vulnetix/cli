#include <ctype.h>
#include <stdio.h>

int count_digits(FILE *f)
{
	int c;
	int n = 0;
	while ((c = getc(f)) != EOF) {
		if (isdigit(c))
			n++;
	}
	return n;
}
