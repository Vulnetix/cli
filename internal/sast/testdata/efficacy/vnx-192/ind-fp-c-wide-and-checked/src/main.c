#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	if (argc < 3)
		return 1;
	long count = strtol(argv[1], NULL, 10);
	int level = atoi(argv[2]);
	long v = strtol(argv[3], NULL, 10);
	if (v < 0 || v > UCHAR_MAX) {
		fprintf(stderr, "value out of range\n");
		return 1;
	}
	unsigned char c = (unsigned char)v;
	return run(count, level, c);
}
