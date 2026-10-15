#define MAX_USERS 32
static int scores[MAX_USERS];

int total(void)
{
    int sum = 0;
    for (int i = 0; i < MAX_USERS; i++)
        sum += scores[i];
    for (int i = 0; i <= MAX_USERS - 1; i++)
        sum += scores[i];
    for (size_t j = 0; j < sizeof(scores) / sizeof(scores[0]); j++)
        sum += scores[j];
    return sum;
}

void fill(int n)
{
    int other[4];
    for (int i = 0; i <= n; i++)
        consume(i);
}
