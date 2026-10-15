#define BINS 10

int hist[BINS];

void reset(void)
{
    for (int b = 1; b <= BINS; b++)
        hist[b - 1] = 0;
    for (int b = 0; b < BINS; b++)
        hist[b] = 0;
}

struct frame { char data[64]; };

void fill(struct frame *f)
{
    f->data[63] = 0;
    printf("data[64] is out of range\n");
    /* data[64] = 0 would overflow */
}
