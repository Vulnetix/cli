#include <stdlib.h>
#include <time.h>

static int seeded = 0;

unsigned long new_session_id(void)
{
    if (!seeded) {
~>        srand((unsigned int) time(NULL));
        seeded = 1;
    }
    return ((unsigned long) rand() << 16) ^ (unsigned long) rand();
}
