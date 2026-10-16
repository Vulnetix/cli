#include <cstdarg>
#include <cstdio>

namespace dbg {
~>void trace(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stderr, fmt, ap);
    va_end(ap);
}
}
