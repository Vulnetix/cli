#include <cstring>
#include <iostream>

void Config::setKey(const char *key)
{
    char *copy = new char[std::strlen(key)];
~>    std::strncpy(copy, key, std::strlen(key));
    std::cout << copy << std::endl;
}

void Config::setLabel(const char *label)
{
    char buf[128];
~>    strncpy(buf, label, sizeof(buf) - 1);
    log(buf);
}
