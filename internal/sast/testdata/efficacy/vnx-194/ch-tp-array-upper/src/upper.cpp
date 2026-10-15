#include <cctype>
#include <cstddef>

void upcase(char name[64], size_t n)
{
    for (size_t i = 0; i < n; i++)
~>        name[i] = std::toupper(name[i]);
}
