#define SMALL 4
#define BIG 8

int small[SMALL];
int big[BIG];

int pick(void)
{
    int k;
    for (k = 0; k <= SMALL; k++)
        big[k] = 1;
    return big[SMALL];
}
