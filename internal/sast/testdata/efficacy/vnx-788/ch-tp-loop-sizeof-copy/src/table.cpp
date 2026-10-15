#include <cstddef>

static int lut[256];

void build_lut(const int *src)
{
~>    for (size_t i = 0; i <= sizeof lut; ++i) {
        lut[i] = src[i] * 2;
    }
}

#define SLOTS 16

void clear_slots(void)
{
    int slots[SLOTS];
    int i;
~>    for (i = 0; i <= SLOTS; i++)
        slots[i] = -1;
}
