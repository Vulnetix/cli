#include <cstdlib>

class Cache {
public:
    void warm()
    {
        char *buf = new char[64];
        fill(buf);
        delete[] buf;
    }

    void flush(char *buf)
    {
        std::free(buf);
    }

private:
    void fill(char *) {}
};
