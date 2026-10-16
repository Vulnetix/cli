#include <cstring>
#include <string>
#include <vector>
void h(const std::string &s)
{
    std::vector<char> out(s.size());
    std::memcpy(out.data(), s.data(), s.size());
    // memcpy(dst, src, strlen(src));
    const char *t = "memcpy(dst, src, strlen(src))";
    (void)t;
}
