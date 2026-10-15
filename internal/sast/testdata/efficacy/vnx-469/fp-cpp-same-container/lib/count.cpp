#include <iterator>
#include <vector>

std::size_t count_all(const std::vector<int>& items)
{
    auto n = std::distance(items.begin(), items.end());
    auto m = items.end() - items.begin();
    return static_cast<std::size_t>(n + m);
}
