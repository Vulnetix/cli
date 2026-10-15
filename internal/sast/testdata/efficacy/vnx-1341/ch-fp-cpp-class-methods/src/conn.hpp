#pragma once
#include <unistd.h>

namespace net {

class Conn {
public:
    explicit Conn(int fd) : fd_(fd) {}

    void shutdown() {
        ::close(fd_);
    }

    ~Conn() {
        if (fd_ >= 0)
            ::close(fd_);
    }

    void reset(char *buf) {
        free(buf);
    }

    void drop(char *buf) {
        free(buf);
    }

private:
    int fd_;
};

}  // namespace net
