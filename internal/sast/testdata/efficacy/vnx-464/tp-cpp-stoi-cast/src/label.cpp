#include <string>

void label(const std::string &in, char out[4])
{
    out[0] = 'L';
~>    out[1] = static_cast<char>(std::stoi(in));
    out[2] = '\0';
}
