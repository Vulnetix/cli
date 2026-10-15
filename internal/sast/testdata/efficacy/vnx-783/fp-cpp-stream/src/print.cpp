#include <iostream>
#include <sstream>

void show(std::ostream &os, int n)
{
    std::cout << 8 + n << std::endl;
    os << 4 + n;
    std::stringstream ss;
    ss << 2 + n << ",";
}
