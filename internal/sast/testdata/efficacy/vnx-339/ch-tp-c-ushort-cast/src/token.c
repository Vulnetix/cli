#include <stdlib.h>
#include <time.h>

unsigned long make_token(void)
{
~>    srand((unsigned short) time(NULL));
    unsigned long token = ((unsigned long) rand() << 16) | rand();
    return token;
}
