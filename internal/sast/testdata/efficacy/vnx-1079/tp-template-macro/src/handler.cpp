#include "handler.h"

~>template <typename T> class EXPORT_API Handler {
public:
    virtual bool handle(T &event) = 0;
};

template <typename T>
~>class Sink
{
  public:
    virtual   void   push(const T &v);
};

void use() {
    Handler<int> *h = make_handler();
    delete h;
}
