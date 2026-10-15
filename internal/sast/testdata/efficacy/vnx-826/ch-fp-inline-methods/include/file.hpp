#pragma once
#include <unistd.h>

class File {
public:
    void reset() {
        ::close(fd_);
    }
    ssize_t write_all(const void *b, size_t n) {
        return ::write(fd_, b, n);
    }
    void reopen(int fd)
    {
        fd_ = fd;
    }

private:
    int fd_ = -1;
};

struct Pipe {
    int rd;
    void shut() { close(rd); }
    long get(char *b, size_t n) { return read(rd, b, n); }
};
