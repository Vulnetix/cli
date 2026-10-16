#include <stdio.h>
#include <string.h>

void print_banner(const char *product, const char *version)
{
	char title[40];

	snprintf(title, sizeof(title), "%s %s", product, version);
	puts(title);
	printf("== %s ==\n", title);
}
