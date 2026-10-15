#include <stdlib.h>
#include <time.h>
#include <sys/random.h>

void init(unsigned char *token, size_t n) {
    srand(time(NULL));
    getrandom(token, n, 0);
    long started = time(NULL);
}
