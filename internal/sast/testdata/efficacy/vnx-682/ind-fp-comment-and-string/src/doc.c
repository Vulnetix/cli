#include <stdio.h>

/* x / 0 is undefined behaviour; never write hits % 0 */
void explain(void)
{
    // return hits / 0;
    puts("hits / 0 traps on x86");
}
