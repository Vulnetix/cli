#define MAX_USERS 32

static int scores[MAX_USERS];

int total_score(void)
{
    int sum = 0;
~>    for (int i = 0; i <= MAX_USERS; i++)
        sum += scores[i];
    return sum;
}
