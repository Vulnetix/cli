#include <cstdint>
#include <cstdlib>

int decode(const uint8_t *in, std::size_t len)
{
    auto *frame = new uint8_t[len];
    for (std::size_t i = 0; i < len; i++)
        frame[i] = in[i] ^ 0x5a;
    int sum = frame[0];
~>    free(frame);
    return sum;
}

void counts(int n)
{
    int *hist = new int[n]();
    hist[0] = 1;
~>    delete hist;
}
