#include <algorithm>
#include <iterator>
#include <vector>

long index_of(const std::vector<int> &items, int needle)
{
    auto it = std::find(items.begin(), items.end(), needle);
    if (it == items.end())
        return -1;
    return std::distance(items.begin(), it);
}

long count_all(const std::vector<int> &items)
{
    return std::distance(items.begin(), items.end());
}
