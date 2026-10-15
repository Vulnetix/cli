#pragma once

class Sink {
public:
    virtual
    ~Sink() = default;
    virtual void write(const char* buf, int n) = 0;
};

struct Source {
    virtual ~Source() noexcept = default;
    virtual int read(char* buf, int n) = 0;
};
