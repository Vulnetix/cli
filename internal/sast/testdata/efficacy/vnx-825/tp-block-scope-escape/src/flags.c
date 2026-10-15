#include <stdio.h>

int parse(const char *s);

void show(int n)
{
    const char *label;
    {
        char tmp[16];
        snprintf(tmp, sizeof tmp, "%d", n);
        label = tmp;
    }
~>    puts(label);
}

static int default_limit = 10;

int limit_of(const char *override)
{
    int *limit = &default_limit;
    if (override) {
        int value = parse(override);
        limit = &value;
    }
~>    return *limit;
}
