#include <cstdarg>
#include <cstdio>
#include <string>

namespace net {

~>std::string Buffer::format(char const *fmt,
                           ...) {
    char tmp[512];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    return std::string(tmp);
}

}  // namespace net
