#include <vector>

void grow(std::vector<int> &slots)
{
    int &head = slots.front();
    slots.emplace_back(0);
~>    head = 7;
}
