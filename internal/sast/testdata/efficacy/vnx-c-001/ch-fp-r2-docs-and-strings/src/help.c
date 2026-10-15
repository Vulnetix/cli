#include <stdio.h>

static const char *help =
	"do not use strcpy(dst, src) or gets(buf) in plugins";

void show_help(void)
{
	/* historic: strcat(path, user); was removed in 2.1 */
	puts(help);
}
