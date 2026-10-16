#include <stdlib.h>

void build_world(int map[64][64], unsigned int level)
{
    int x, y;
    srand(level % 100);
    for (y = 0; y < 64; y++)
        for (x = 0; x < 64; x++)
            map[y][x] = rand() % 4;
}
