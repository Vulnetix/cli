#pragma once

template <typename T>
class Stream {
public:
    virtual ~Stream() {}
    virtual T read() = 0;
};

class NonCopyable {
protected:
    NonCopyable() = default;
};

class Socket : private NonCopyable, public Stream<char> {
public:
    Socket(int fd);
~>    ~Socket() = default;
    char read() override;
};
