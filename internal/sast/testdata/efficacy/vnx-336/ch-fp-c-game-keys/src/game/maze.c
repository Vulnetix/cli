#include <stdlib.h>
#include <curses.h>

void start_level(void)
{
    srand(42);
    int dir = rand() % 4;
    int key = getch();
    handle_key(key, dir);
}
