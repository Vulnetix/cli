#include <fstream>

void load(const char *path) {
    std::ifstream in(path);
    char key[16];
~>    in >> key;
    apply(key);
}
