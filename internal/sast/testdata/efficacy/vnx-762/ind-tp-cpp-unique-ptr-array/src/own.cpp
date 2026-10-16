#include <memory>

void own(size_t n)
{
~>    std::unique_ptr<char> buf(new char[n]);
    buf.get()[0] = 'a';
}
