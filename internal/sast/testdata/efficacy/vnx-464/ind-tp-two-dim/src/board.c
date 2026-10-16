#include <stdlib.h>

static char grid[8][8];

void place(int r, int c, const char *cell)
{
~>    grid[r][c] = atoi(cell);
}
