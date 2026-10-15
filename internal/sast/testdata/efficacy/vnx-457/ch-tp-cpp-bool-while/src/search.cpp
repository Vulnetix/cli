#include <vector>

int findIndex(const std::vector<int> &v, int needle)
{
    bool found;
    int i = 0;
~>    while (!found && i < (int)v.size()) {
        found = v[i] == needle;
        ++i;
    }
    return found ? i - 1 : -1;
}
