#include <iostream>
#include "cache.h"

void Cache::dump() const
{
    unsigned long hits;

~>    std::cout << "cache hits: " << hits << '\n';
    for (const auto &e : entries_) {
        std::cout << e.first << '\n';
    }
}
