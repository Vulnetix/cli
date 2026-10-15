#include <unistd.h>
#include <cstdio>

class FileHandle {
public:
    explicit FileHandle(int fd) : fd_(fd) {}
    ~FileHandle() {
        if (fd_ >= 0) close(fd_);
    }

private:
    int fd_;
};

class Holder {
public:
    ~Holder() = default;
};

void release(char* p) {
    free(p);
}
