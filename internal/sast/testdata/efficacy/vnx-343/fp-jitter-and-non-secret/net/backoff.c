#include <stdlib.h>

int next_backoff(int last_backoff)
{
    int backoff = last_backoff + (rand() % 100);
    return backoff;
}
