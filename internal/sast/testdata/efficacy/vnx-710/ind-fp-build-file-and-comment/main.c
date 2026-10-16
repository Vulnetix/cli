#include <stdio.h>

/*
 * The build used to rely on
 * #pragma GCC diagnostic ignored "-Warray-bounds"
 * which has been removed.
 */
int main(void)
{
    puts("ok");
    return 0;
}
