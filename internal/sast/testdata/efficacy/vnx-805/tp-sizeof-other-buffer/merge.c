#include <string.h>

void merge(const char *input) {
    char small[8];
    char big[128];
    memcpy(big, input, sizeof(big));
~>    memcpy(small, input, sizeof(big));
}
