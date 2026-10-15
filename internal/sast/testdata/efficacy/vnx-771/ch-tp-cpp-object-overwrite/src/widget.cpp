#include "widget.h"

void rebuild()
{
~>    Widget *w = new Widget(1);
    w->init();
    w = new Widget(2);
    w->init();
    delete w;
}
