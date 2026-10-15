#define MAX_USERS 32

static int scores[MAX_USERS];

int total(void)
{
    int sum = 0;
~>    for (int i = 0; i <= MAX_USERS; i++) {
        sum += scores[i];
    }
    return sum;
}

int find(int needle)
{
    char names[10];
    int k;
~>    for (k = 0; k <= 10; ++k)
        if (names[k] == needle)
            return k;
    return -1;
}
