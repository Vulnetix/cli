#include <string>
#include <vector>

class Buffer {
    char data_[64];
    std::string name_;
public:
    char *data() {
        return data_;
    }
    const char *name() const {
        return name_.c_str();
    }
};

std::string display_name(int id) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "user-%d", id);
    return buf;
}

std::string label() {
    std::string s = "x";
    return s.c_str();
}

const std::string &shared_title() {
    static std::string title = "home";
    return title;
}

int &slot(std::vector<int> &v, int i) {
    int &ref = v[i];
    return ref;
}
