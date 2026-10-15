#define N 10
#include <string.h>

int sum(void)
{
    int vals[N];
    int total = 0;
    for (int i = 0; i < N; i++)
        total += vals[i];
    return total;
}

void set_name(const char *src)
{
    char name[32];
    strncpy(name, src, sizeof(name) - 1);
    name[sizeof(name) - 1] = '\0';
    name[31] = 0;
}
