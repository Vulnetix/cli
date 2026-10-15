#include <vector>
#include <algorithm>

long count_before(const std::vector<int> &v, int x)
{
    auto it = std::find(v.begin(), v.end(), x);
    long idx = it - v.begin();
    long total = v.end() - v.begin();
    return total - idx;
}
