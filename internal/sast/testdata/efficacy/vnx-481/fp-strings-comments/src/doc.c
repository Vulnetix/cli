#include <stdio.h>

/* Bug pattern: if (x = 0) always false */
// while (done = 1) loops forever
int main(void)
{
    puts("never write if (x = 0)");
    return 0;
}
