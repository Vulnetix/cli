#include <stdlib.h>
#include <vector>

std::vector<unsigned char> make_key(size_t n)
{
    std::vector<unsigned char> key(n);
    arc4random_buf(key.data(), key.size());
    return key;
}
