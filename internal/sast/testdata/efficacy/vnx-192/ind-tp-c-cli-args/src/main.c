#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	if (argc < 4) {
		fprintf(stderr, "usage: %s workers port bufsize\n", argv[0]);
		return 1;
	}
~>	unsigned char workers = atoi(argv[1]);
~>	uint16_t port = (uint16_t)strtol(argv[2], NULL, 10);
~>	size_t bufsize = atol(argv[3]);
	char *buf = malloc(bufsize);
	return run(workers, port, buf, bufsize);
}
