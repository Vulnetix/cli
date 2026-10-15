#include <cstdio>

~>#pragma GCC diagnostic ignored "-Wformat-security"
~>#pragma clang diagnostic ignored "-Wformat-nonliteral"
~>#pragma GCC diagnostic ignored "-Wall"
~>#  pragma clang diagnostic ignored "-Weverything"

void log_line(const char *msg) {
    std::printf(msg);
}
