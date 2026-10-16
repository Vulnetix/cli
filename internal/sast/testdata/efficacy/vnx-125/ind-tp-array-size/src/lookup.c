#include <string.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static const char *commands[] = { "start", "stop", "status", "reload" };

int find_command(const char *key)
{
~>    for (size_t i = 0; i <= ARRAY_SIZE(commands); ++i) {
        if (strcmp(commands[i], key) == 0)
            return (int)i;
    }
    return -1;
}
