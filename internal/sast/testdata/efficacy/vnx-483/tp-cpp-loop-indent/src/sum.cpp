#include <vector>

int total(const std::vector<int> &v, int &count)
{
    int sum = 0;
    for (size_t i = 0; i < v.size(); i++)
        sum += v[i];
~>        count++;
    while (sum > 100)
        sum -= 100;
~>        count--;
    return sum;
}
