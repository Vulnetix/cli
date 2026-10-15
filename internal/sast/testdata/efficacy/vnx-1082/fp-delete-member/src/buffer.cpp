#include "buffer.h"

Buffer::~Buffer() {
    delete this->header_;
    delete[] data_;
    delete thisFrame_;
    delete this_node;
}

void Buffer::swap(Buffer* other) {
    delete other;
}
