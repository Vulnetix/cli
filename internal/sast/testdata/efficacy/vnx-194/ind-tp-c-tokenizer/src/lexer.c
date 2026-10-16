#include <ctype.h>
#include <stddef.h>

size_t next_token(const char *src, size_t pos, char *tok, size_t tok_len)
{
	size_t n = 0;

~>	while (src[pos] && isspace(src[pos]))
		pos++;
~>	while (src[pos] && isalnum(src[pos]) && n + 1 < tok_len)
		tok[n++] = src[pos++];
	tok[n] = '\0';
	return pos;
}
