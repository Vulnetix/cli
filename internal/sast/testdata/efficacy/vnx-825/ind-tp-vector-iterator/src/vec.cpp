#include <vector>

void grow(std::vector<int> &items, int extra)
{
    auto it = items.begin();
    items.push_back(extra);
~>    *it = 0;
}

void loop(std::vector<int> &v)
{
    for (int x : v) {
~>        v.push_back(x);
    }
}
