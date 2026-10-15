#include <stdio.h>

int main(int argc, char **argv)
{
	char fmt[128];
	char out[256];
~>	fprintf(stderr, argv[1]);
	if (!fgets(fmt, sizeof fmt, stdin))
		return 1;
~>	snprintf(out, sizeof out, fmt, argc);
	return 0;
}
