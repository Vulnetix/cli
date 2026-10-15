#include <cstring>
#include <string>
#include <vector>

std::vector<char> to_bytes(const std::string &s)
{
    std::vector<char> out(s.size());
    std::memcpy(out.data(), s.data(), s.size());
    return out;
}

void into(std::string &dst, const std::string &src)
{
    dst.resize(src.size());
    std::memcpy(&dst[0], src.c_str(), src.size());
}
