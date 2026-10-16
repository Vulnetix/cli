#include <cstddef>
~>class Codec {
    int level_ = 0;
public:
    ~Codec() { flush(); }
    virtual int encode(const char *in, char *out);
private:
    void flush();
};
