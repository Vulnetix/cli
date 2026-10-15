#include <cstdlib>
#include <string>

void patchLabel(char label[32], const std::string &arg)
{
~>    label[4] = static_cast<char>(std::strtoul(arg.c_str(), nullptr, 10));
}
