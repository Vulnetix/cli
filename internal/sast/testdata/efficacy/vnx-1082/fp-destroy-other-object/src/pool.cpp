#include <new>
#include "pool.h"

void Pool::release(Item* item) {
    item->~Item();
    slots_.push_back(item);
}

void Pool::clear() {
    for (auto* it : live_) {
        it->~Item();
    }
    std::unique_ptr<Item> owned(make());
    owned.reset();
}
