#include "token.hpp"

bool Tokenizer::at_end(std::size_t i)
{
~>    if (buf_[i] = '\0')
        return true;
    return false;
}
