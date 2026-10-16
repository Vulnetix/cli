#include "conn.hpp"

int Conn::open()
{
    if (int err = connect_socket(fd_); err != 0) {
        return err;
    }
    for (int i = 0; i < retries_; i++) {
        attempts_ = i;
    }
    return 0;
}
