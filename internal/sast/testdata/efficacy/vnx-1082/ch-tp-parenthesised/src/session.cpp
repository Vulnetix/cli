#include "session.h"

void Session::close() {
    socket_.shutdown();
~>    delete (this);
}
