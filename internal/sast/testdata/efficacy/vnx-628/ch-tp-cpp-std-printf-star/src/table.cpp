#include <cstdio>
#include <string>

void row(int width, const std::string &name, double v) {
~>    std::printf("%*s|\n", name.c_str());
~>    std::snprintf(buf, sizeof(buf), "%s=%.2f", name.c_str());
    std::printf("%*s|%.2f\n", width, name.c_str(), v);
}
