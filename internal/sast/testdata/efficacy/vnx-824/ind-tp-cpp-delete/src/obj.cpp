#include <string>

void use_string()
{
    std::string *s;
~>    delete s;
    int *buf;
~>    buf[3] = 7;
}
