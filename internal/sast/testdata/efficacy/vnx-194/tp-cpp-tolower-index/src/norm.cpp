#include <cctype>
#include <string>

void lower_in_place(char *buf, std::size_t n)
{
    for (std::size_t i = 0; i < n; i++) {
~>        buf[i] = std::tolower(buf[i]);
    }
}

void upper(char name[64])
{
~>    name[0] = toupper(name[0]);
}
