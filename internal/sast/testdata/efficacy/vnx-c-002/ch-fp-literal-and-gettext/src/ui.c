#include <stdio.h>
#include <libintl.h>

#define FMT_ROW "%-10s %5d\n"

void row(const char *name, int n)
{
	printf(FMT_ROW, name, n);
	printf(_("Hello %s\n"), name);
	printf("%s", name);
	fprintf(stderr, "error: %s\n", name);
	printf("done\n");
	fputs(name, stdout);
	snprintf(buf, sizeof buf, "%s", name);
}
