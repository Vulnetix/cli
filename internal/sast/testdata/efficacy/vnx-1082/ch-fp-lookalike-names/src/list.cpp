#include "list.h"

void List::clear() {
    Node* thisNode = head_;
    while (thisNode) {
        Node* next = thisNode->next;
        delete thisNode;
        thisNode = next;
    }
    delete this->sentinel_;
    delete this_ptr_;
    delete[] this->buffer_;
}

void List::log() {
    logger_.info("calling delete this; is forbidden here");
    printf("this->~List() not called\n");
}
