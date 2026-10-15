#include "session.hpp"

void Session::pause()
{
    for (int i = 0; i < spins_; ++i) {
~>        asm("pause");
    }
}

bool Session::flag() const
{
    bool r;
~>    asm volatile (
        "bt %1, %2\n\t"
        "setc %0"
        : "=r"(r) : "r"(bit_), "r"(word_));
    return r;
}
