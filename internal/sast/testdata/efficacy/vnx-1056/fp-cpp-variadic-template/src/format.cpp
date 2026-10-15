#include <cstdio>
#include <string>
#include <utility>

template <typename... Args>
std::string format_message(const char *fmt, Args&&... args) {
    char buf[256];
    std::snprintf(buf, sizeof buf, fmt, std::forward<Args>(args)...);
    return std::string(buf);
}

void log_twice(const char *fmt) {
    std::puts(fmt);
    std::puts("...");
}
