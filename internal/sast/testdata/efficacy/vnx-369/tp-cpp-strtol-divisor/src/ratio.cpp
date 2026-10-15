#include <cstdlib>
#include <iostream>

int main(int argc, char **argv)
{
    long parts = std::strtol(argv[2], nullptr, 10);
    long whole = std::strtol(argv[1], nullptr, 10);
~>    std::cout << whole / parts << std::endl;
    return 0;
}
