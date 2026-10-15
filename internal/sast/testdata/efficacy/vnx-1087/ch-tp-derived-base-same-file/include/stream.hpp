#pragma once

class StreamBase {
public:
    int fd() const;
    ~StreamBase();
};

~>class Stream : public StreamBase {
public:
    virtual long read(char* buf, long n) = 0;
    virtual long write(const char* buf, long n) = 0;
};
