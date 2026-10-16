#include <cstdio>

#pragma warning(push)
#pragma warning(error: 4996)
#pragma warning(default: 4789)
void safe_print(const char *s)
{
    std::printf("%s\n", s);
}
#pragma warning(pop)

static const char *kHelp = "define _CRT_SECURE_NO_WARNINGS only in legacy builds";
// Do not add #pragma warning(disable: 4996) here; fix the call instead.
