#include "retry.hpp"

void Backoff::fail()
{
~>    remaining =- 1;
    if (remaining <= 0) {
        give_up();
    }
}
