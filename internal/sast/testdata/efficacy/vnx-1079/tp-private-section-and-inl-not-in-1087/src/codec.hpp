#pragma once

~>class Codec {
    int level_ = 0;
public:
    Codec() = default;
    ~Codec() { flush(); }
    virtual int encode(const char *in, char *out);
private:
    void flush();
};

~>struct Sink {
    virtual void write(const char *buf, int len);
    ~Sink();
protected:
    int written_ = 0;
};
