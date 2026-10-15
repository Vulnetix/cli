#include <stdio.h>

/* memset(buf, sizeof(buf), 0) is a classic bug */
// printf("%s %s\n", a);
static const char *help = "call memset(p, n, 0) wrongly";

void usage(void)
{
	puts(help);
}
