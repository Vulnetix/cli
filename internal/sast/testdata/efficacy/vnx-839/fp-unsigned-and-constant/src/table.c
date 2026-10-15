#include <stdlib.h>

static char *names[16];

int set_name(const char *arg, char *value)
{
    unsigned long idx = strtoul(arg, NULL, 10);
    if (idx >= 16)
        return -1;
    names[idx] = value;
    return 0;
}

int fixed(void)
{
    int k = 3;
    if (k < 16)
        return names[k] != NULL;
    return 0;
}

int checked(const char *arg)
{
    int i = atoi(arg);
    if (i < 0 || i >= 16)
        return -1;
    return names[i] != NULL;
}
