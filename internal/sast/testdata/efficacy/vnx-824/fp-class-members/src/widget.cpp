#include <string>

class Widget {
public:
    explicit Widget(std::string *label) : label_(label) {}
    void rename(const std::string &s) {
        label_->assign(s);
    }
private:
    std::string *label_;
    int *counts_;
};

struct config {
    char *path;
    int verbose;
};

const char *path_of(const struct config *c)
{
    return c->path;
}
