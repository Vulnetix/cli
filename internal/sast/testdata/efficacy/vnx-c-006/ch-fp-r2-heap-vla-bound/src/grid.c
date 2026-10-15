#include <stdlib.h>

#define MAX_COLS 64

int grid_sum(const char *arg)
{
	int cols = atoi(arg);
	if (cols < 1 || cols > MAX_COLS)
		return -1;
	int row[cols];
	int *heap = malloc(cols * sizeof(int));
	free(heap);
	row[0] = 0;
	return row[0];
}
