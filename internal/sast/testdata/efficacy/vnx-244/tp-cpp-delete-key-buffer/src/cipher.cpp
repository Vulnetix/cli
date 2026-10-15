#include <cstdlib>

Cipher::~Cipher()
{
~>    delete[] aes_key;
~>    std::free(master_key_);
}
