#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int set_title(char *dst, size_t cap, const char *title)
{
	if (strlen(title) >= cap)
		return -1;
	strcpy(dst, title);
	return 0;
}

char *dupe(const char *s)
{
	char *d = malloc(strlen(s) + 1);
	if (!d)
		return NULL;
	strcpy(d, s);
	return d;
}

void fmt_name(char *out, size_t n, const char *name)
{
	snprintf(out, n, "%s", name);
	strlcpy(out, name, n);
	strncat(out, name, n - strlen(out) - 1);
}

void fmt_short(char *out, const char *name)
{
	sprintf(out, "%.31s", name);
}

int read_word(char *w)
{
	return scanf("%63s", w);
}
