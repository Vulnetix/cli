#include <cstdlib>

void Frame::release() {
~>    std::free(payload_ + kHeaderLen);
}
