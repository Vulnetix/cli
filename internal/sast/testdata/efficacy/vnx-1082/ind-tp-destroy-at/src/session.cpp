#include <memory>
#include <new>
#include "session.h"

void Session::reset() {
~>    std::destroy_at(this);
    new (this) Session();
}

void Session::wipe() {
~>    this->~Session();
    new (this) Session();
}
