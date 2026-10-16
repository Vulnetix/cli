#include "x.h"
// Do not call delete this; here, the owner frees us.
/* this->~X(); would be wrong */
void X::go() {
    const char* msg = "delete this; is dangerous";
    log(msg);
}
