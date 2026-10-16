#include "msg.h"

Msg::~Msg() {
    delete this->header_;
    delete[] data_;
    delete other_;
}

void Pool::recycle(Item* item) {
    item->~Item();
    free_list_.push_back(item);
}
