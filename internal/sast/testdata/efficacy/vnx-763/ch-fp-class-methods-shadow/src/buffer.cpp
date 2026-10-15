#include <cstdlib>
#include <cstring>

class Buffer {
public:
    void stage(const char *src)
    {
        char tmp[32];
        std::strncpy(tmp, src, sizeof tmp);
        apply(tmp);
    }

    void drop()
    {
        char *tmp = static_cast<char *>(std::malloc(32));
        apply(tmp);
        std::free(tmp);
    }

private:
    void apply(char *) {}
};
