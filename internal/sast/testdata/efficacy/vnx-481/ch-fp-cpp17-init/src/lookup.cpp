#include <map>
#include <string>

int find(const std::map<std::string, int> &m, const std::string &k)
{
    if (auto it = m.find(k); it != m.end()) {
        return it->second;
    }
    if (const char *v = getenv("X")) {
        return 1;
    }
    return 0;
}
