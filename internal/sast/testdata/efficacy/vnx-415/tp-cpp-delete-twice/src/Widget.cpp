#include "Widget.h"

void Widget::reset(bool hard)
{
    delete renderer;
    if (hard) {
        clearState();
    }
~>  delete renderer;
    renderer = nullptr;
}

void Widget::dropBuffer()
{
    delete[] buffer;
    notifyListeners();
~>  delete [] buffer;
}
