#include <stdio.h>

/* Bad: char *out = malloc(strlen(name)); strcpy(out, name); */
static const char *HINT = "use malloc(strlen(s) + 1), not malloc(strlen(s))";

void print_hint(void)
{
	/* for (i = 0; i <= N; i++) arr[i] = 0; is one past the end */
	puts(HINT);
}
