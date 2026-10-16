#include <stdlib.h>

void set_mode(char *mode, const char *level)
{
    int lvl = atoi(level);
    mode[0] = 'r';
    mode[1] = '+';
    mode[2] = '\0';
    (void)lvl;
}
