#include <string>
#include <vector>

std::vector<char> make(const std::string &arg)
{
    int n = std::stoi(arg);
~>    std::vector<char> v(n);
    return v;
}
