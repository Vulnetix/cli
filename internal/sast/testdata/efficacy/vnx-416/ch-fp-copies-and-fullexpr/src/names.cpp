#include <string>
#include <string_view>
#include <cstdio>

std::string normalise(std::string_view in, int n)
{
    std::string copy = std::string(in).c_str();
    std::printf("%s\n", std::to_string(n).c_str());
    const std::string &held = std::to_string(n);
    std::string_view lit = "fixed";
    puts(held.c_str());
    log_line((copy + "!").c_str(), lit.data());
    return copy;
}
