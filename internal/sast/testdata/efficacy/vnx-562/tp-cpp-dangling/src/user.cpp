#include <string>
#include <vector>

const char *display_name(int id) {
    std::string label = "user-" + std::to_string(id);
~>    return label.c_str();
}

const int *scores() {
    std::vector<int> v{1, 2, 3};
~>    return v.data();
}

std::string &cached_title() {
    std::string title = "home";
~>    return title;
}

class Formatter {
public:
    const char *render(int n) const {
        char out[32];
        std::snprintf(out, sizeof(out), "%d", n);
~>        return out;
    }
};
