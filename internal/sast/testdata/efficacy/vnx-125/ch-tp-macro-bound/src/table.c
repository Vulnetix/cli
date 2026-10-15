#define SLOTS 8

static int slots[SLOTS];

int sum(void)
{
    int total = 0;
~>    for (int k = 0; k <= SLOTS; ++k) {
        total += slots[k];
    }
    return total;
}
