#pragma once
#include <cstring>

#if defined(__GNUC__)
#define COMPAT_PUSH _Pragma("GCC diagnostic push")
~>#define COMPAT_NO_STRINGOP _Pragma("GCC diagnostic ignored \"-Wstringop-overflow\"")
#define COMPAT_POP _Pragma("GCC diagnostic pop")
#else
#define COMPAT_PUSH
#define COMPAT_NO_STRINGOP
#define COMPAT_POP
#endif

namespace compat {
inline void fill(char *dst, const char *src, std::size_t n)
{
    COMPAT_PUSH
    COMPAT_NO_STRINGOP
    std::memcpy(dst, src, n);
    COMPAT_POP
}
}  // namespace compat
