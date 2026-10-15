#include "widget.h"

Widget::~Widget() { this->cleanup(); }

Widget::~Widget2() = default;

void Pool::destroy(Item* item) {
    item->~Item();
    (*item).~Item();
    free_.push_back(item);
}

/*
 * Never write `delete this;` in a component: the owner frees it.
 */
// this->~Widget();
