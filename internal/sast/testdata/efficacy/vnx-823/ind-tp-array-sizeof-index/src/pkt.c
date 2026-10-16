#include <string.h>
#include <stdint.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

int copy_name(const char *src)
{
    char name[32];
    strncpy(name, src, sizeof(name));
~>    name[sizeof(name)] = '\0';
    return 0;
}

const char *lookup(int i)
{
    static const char *names[] = {"a", "b", "c"};
    if (i < 0) return NULL;
~>    return names[ARRAY_SIZE(names)];
}
