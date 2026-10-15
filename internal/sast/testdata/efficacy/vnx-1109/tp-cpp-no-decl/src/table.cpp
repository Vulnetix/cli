#include <vector>

int count(const std::vector<std::vector<int>>& t) {
    size_t j;
    int n = 0;
    for (j = 0; j < t.size(); ++j)
    {
~>        for (j = 0; j < t[j].size(); ++j)
        {
            n += t[j][0];
        }
    }
    return n;
}
