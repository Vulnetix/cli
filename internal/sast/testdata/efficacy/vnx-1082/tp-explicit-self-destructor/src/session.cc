#include <new>
#include "session.h"

void Session::reset() {
~>    this->~Session();
    new (this) Session();
}

void Session::teardown() {
~>    (*this).~Session();
}

~>void Session::finish() { cleanup(); this -> ~Session(); }
