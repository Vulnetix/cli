#include <iterator>
#include <vector>

long merged_size(const std::vector<int> &left, const std::vector<int> &right)
{
~>    auto n = std::distance(left.begin(), right.end());
    return static_cast<long>(n);
}
