#include <iterator>
#include <vector>

std::size_t merged_size(const std::vector<int>& left, const std::vector<int>& right)
{
~>    auto n = std::distance(left.begin(), right.end());
~>    auto m = right.end() - left.begin();
    return static_cast<std::size_t>(n + m);
}

std::size_t block_gap()
{
    char *front = new char[64];
    char *back = new char[64];
~>    std::size_t gap = back - front;
    delete[] front;
    delete[] back;
    return gap;
}
