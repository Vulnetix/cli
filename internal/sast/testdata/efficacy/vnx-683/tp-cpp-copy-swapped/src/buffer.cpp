#include <cstring>

void Buffer::assign(const char *src, char *dst, std::size_t len) {
~>    std::memcpy(src, dst, len);
~>    std::memset(dst, len, 0);
}
