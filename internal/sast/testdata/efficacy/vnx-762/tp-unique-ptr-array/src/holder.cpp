#include <memory>

void hold(size_t n) {
~>    std::unique_ptr<char> buf(new char[n]);
~>    std::shared_ptr<int> ids(new int[16]);
    std::unique_ptr<char[]> ok(new char[n]);
    std::shared_ptr<int> one(new int(5));
}
