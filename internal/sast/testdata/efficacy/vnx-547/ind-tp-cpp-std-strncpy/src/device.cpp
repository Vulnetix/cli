#include <cstring>
#include <string>

void Device::setLabel(const std::string &label)
{
    char name[64];
~>    std::strncpy(name, label.c_str(), 64);
    name[63] = '\0';
    driver_->rename(name);
}
