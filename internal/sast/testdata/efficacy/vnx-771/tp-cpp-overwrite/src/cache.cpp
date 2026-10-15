#include <cstdlib>
#include <cstring>

void Cache::reset(std::size_t n) {
~>    data_ = static_cast<char *>(std::realloc(data_, n));
}

void Cache::rebuild(std::size_t n) {
~>    char *block = new char[n];
    std::memset(block, 0, n);
    block = new char[n * 2];
    delete[] block;
}
