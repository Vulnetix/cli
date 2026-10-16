#pragma once

template <typename T>
class Stream {
public:
    virtual ~Stream() {}
    virtual void write(const T *p, int n) = 0;
};

class NonCopyable {
protected:
    NonCopyable() = default;
    ~NonCopyable() = default;
};

class Socket : private NonCopyable, public Stream<char> {
public:
    void write(const char *p, int n) override;
~>    ~Socket() = default;
};
