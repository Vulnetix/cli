#define EQ(a, b) ((a) == (b))

int eq(int a, int b)
{
    int r = a == b;
    return a == b ||
           r == 1;
}
