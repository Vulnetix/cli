#include <vector>

long span(const std::vector<int> &left, const std::vector<int> &right)
{
~>    long n = right.end() - left.begin();
    return n;
}
