#include <stdlib.h>

#define MAX_TOTAL_BYTES (64 * 1024 * 1024)

int fill(char **buffers, const char *arg)
{
    int n = atoi(arg);
    size_t total = 0;
    for (int i = 0; i < n; i++) {
        if (total + 4096 > MAX_TOTAL_BYTES) {
            return -1;
        }
        buffers[i] = malloc(4096);
        total += 4096;
    }
    return 0;
}
