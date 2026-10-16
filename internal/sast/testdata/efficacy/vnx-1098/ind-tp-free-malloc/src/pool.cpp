#include <cstdlib>
#include <cstring>

class Pool {
public:
    Pool(std::size_t n) { mem_ = (unsigned char*)malloc(n); std::memset(mem_, 0, n); }
~>    ~Pool() {
        free(mem_);
    }
private:
    unsigned char* mem_;
};
