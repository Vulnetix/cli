#include <cstdio>
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static const int codes[] = {200, 301, 404, 500};

void dump()
{
~>    for (size_t i = 0; i <= ARRAY_SIZE(codes); i++)
        std::printf("%d\n", codes[i]);
}
