#include <ctype.h>
#include <stdio.h>

int next_word(FILE *f)
{
	int ch;
	while ((ch = getc(f)) != EOF && isspace(ch))
		;
	return ch == EOF ? -1 : tolower(ch);
}
