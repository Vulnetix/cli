#include <stdlib.h>
#include <stdint.h>

int main(int argc, char **argv)
{
~>	short count = atoi(argv[1]);
~>	uint16_t port = strtoul(argv[2], NULL, 10);
~>	size_t len = atoi(argv[3]);
	return run(count, port, len);
}
