#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	unsigned long id;
	int shards;

	if (argc < 3)
		return 1;
	id = strtoul(argv[1], NULL, 10);
	shards = atoi(argv[2]);
~>	printf("shard %lu\n", id % shards);
	return 0;
}
