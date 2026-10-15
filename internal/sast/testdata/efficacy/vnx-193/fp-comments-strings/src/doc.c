#include <stdio.h>

/* Never write buf[sizeof(buf)] = 0; and never malloc(strlen(s)) for a copy. */
// for (i = 0; i <= SLOTS; i++) slots[i] = 0;
static const char *hint = "strncat(path, user, sizeof(path))";

int main(void)
{
	puts(hint);
	return 0;
}
