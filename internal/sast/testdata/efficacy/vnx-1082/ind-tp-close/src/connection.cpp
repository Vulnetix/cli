#include <unistd.h>
#include "connection.h"

void Connection::close() {
    ::close(socket_);
    notify_closed(id_);
~>    delete this;
}
