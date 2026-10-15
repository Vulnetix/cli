#include <stdio.h>

void report(FILE *out, const char *user, int code, long bytes)
{
~>	printf("user %s failed with %d\n", user);
~>	fprintf(out, "%s: %d bytes\n", user, code, bytes);
~>	fprintf(stderr, "error %d at %s line %d\n", code, user);
	printf("user %s code %d bytes %ld\n", user, code, bytes);
	printf("100%% done for %s\n", user);
	char line[64];
~>	sprintf(line, "%s-%s", user);
}
