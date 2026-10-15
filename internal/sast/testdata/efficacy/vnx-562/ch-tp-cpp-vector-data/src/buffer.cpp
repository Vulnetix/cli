#include <vector>
#include <cstring>

int *make_values(std::size_t n)
{
    std::vector<int> v(n, 0);
~>    return v.data();
}

char *scratch(void)
{
    char buf[128];
    std::memset(buf, 0, sizeof buf);
~>    return &buf[0];
}
