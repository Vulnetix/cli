#include <cstdlib>

static char scratch[4096];

void reset()
{
~>    std::free(scratch);
}

int checksum(const int *in)
{
    int window[16] = {0};
    for (int i = 0; i < 16; i++)
        window[i] = in[i];
    int s = window[0] + window[15];
~>    delete[] window;
    return s;
}
