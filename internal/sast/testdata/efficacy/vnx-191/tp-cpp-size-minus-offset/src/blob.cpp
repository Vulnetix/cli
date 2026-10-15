#include <cstring>
#include <vector>

void Blob::slice(std::vector<char> &out, const char *data, std::size_t size, std::size_t offset) const
{
    out.resize(512);
~>    std::memcpy(out.data(), data + offset, size - offset);
}
