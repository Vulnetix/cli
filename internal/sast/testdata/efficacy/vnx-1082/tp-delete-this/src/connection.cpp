#include "connection.h"

void Connection::close() {
    if (socket_ >= 0) {
        ::close(socket_);
        socket_ = -1;
    }
~>    delete this;
}

void Connection::onError(int code) {
    log_error(code);
~>    delete    this ;
}
