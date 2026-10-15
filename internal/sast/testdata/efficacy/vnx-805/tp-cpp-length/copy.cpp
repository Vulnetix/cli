#include <cstring>
#include <string>

void copy_blob(const char *data, char **argv) {
    char buf[8];
~>    std::memcpy(buf, data, 16);
    std::size_t count = std::stoul(argv[1]);
    char out[64];
~>    std::memcpy(out, data, count);
}
