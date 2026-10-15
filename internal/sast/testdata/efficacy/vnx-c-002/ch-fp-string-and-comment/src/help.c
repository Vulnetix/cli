#include <stdio.h>

/* Never write printf(buf); always printf("%s", buf). */
static const char *help = "use printf(msg) carefully";

void help_text(void)
{
	// fprintf(stderr, msg);
	puts(help);
}
