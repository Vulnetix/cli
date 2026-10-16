#include <cstdio>
#include <string>

std::string render(const char *tag, int level, double t, int width)
{
    char buf[256];
~>    snprintf(buf, sizeof(buf), "[%s] level=%d t=%.3f", tag, level);
    std::string out(buf);
~>    std::snprintf(buf, sizeof(buf), "%*s|", tag);
    out += buf;
    std::snprintf(buf, sizeof(buf), "%*s|%.*f", width, tag, 2, t);
    return out + buf;
}
