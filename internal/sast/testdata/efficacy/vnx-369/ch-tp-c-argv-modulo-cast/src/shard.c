#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	long shards = strtol(argv[1], NULL, 10);
	unsigned long key = 123456789UL;
~>	printf("%lu\n", key % (unsigned long)shards);
	return 0;
}
