#include "widget.h"

// Never call `delete this;` from a method: ownership belongs to the parent.
/* this->~Widget(); was removed in 2.3 */
void Widget::destroy() {
    logger_.warn("refusing to delete this; the parent owns the widget");
    parent_->removeChild(this);
}
