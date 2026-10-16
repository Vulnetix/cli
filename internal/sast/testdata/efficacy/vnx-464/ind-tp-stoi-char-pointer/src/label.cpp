#include <string>
#include <cstddef>

void set_label_byte(char *label, std::size_t idx, const std::string &s)
{
~>    label[idx] = std::stoi(s);
}
