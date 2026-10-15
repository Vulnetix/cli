#include <iomanip>
#include <iostream>

int main() {
    char name[32];
    std::cin >> std::setw(sizeof name) >> name;
    std::cout << name << std::endl;
    return 0;
}
