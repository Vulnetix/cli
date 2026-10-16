#include <cstddef>
#include <vector>

void reset(int (&slots)[16], std::vector<int> &v)
{
    size_t i;
~>    for (i = 0; i <= sizeof(slots) / sizeof(slots[0]); i++)
        slots[i] = 0;
~>    for (size_t j = 0; j <= v.size(); ++j)
        v[j] = 0;
}
