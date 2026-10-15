#include <cstdarg>
#include <cstdio>

#include "logger.h"

~>void Logger::write(int severity, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    std::vfprintf(stream_, fmt, args);
    va_end(args);
}

namespace net {

~>int send_line(Connection &conn, char const *format, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, format);
    int n = std::vsnprintf(buf, sizeof buf, format, ap);
    va_end(ap);
    return conn.write(buf, n);
}

}  // namespace net
