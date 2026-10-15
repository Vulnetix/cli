#include <cstring>

class Label {
public:
    void assign(const char *text) {
~>        std::strncpy(buf_, text, std::strlen(text));
    }
private:
    char buf_[40];
};
