#include <cstdio>

static double weights[12] = {0};

void dump_weights()
{
~>    for (unsigned k = 0; k <= sizeof(weights) / sizeof(weights[0]); k++) {
        std::printf("%u=%f\n", k, weights[k]);
    }
}
