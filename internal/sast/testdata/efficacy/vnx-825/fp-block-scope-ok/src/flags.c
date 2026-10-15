#include <stdio.h>

void show(int n)
{
    const char *label = "none";
    {
        char tmp[16];
        snprintf(tmp, sizeof tmp, "%d", n);
        label = tmp;
        puts(label);
    }
    label = "done";
    puts(label);
}

int parse(const char *s);

int pick(const char *override)
{
    int *limit;
    int fallback = 3;
    if (override) {
        int value = parse(override);
        limit = &value;
        return *limit;
    }
    limit = &fallback;
    return *limit;
}
