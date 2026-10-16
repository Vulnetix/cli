#include <iomanip>
#include <iostream>
#include <string>

int main() {
    std::string name;
    int age = 0;
    char code[8];
    std::cin >> name >> age;
    std::cin >> std::setw(sizeof code) >> code;
    unsigned flags = 0xF0;
    unsigned hi = flags >> 4;
    return name.empty() || hi == 0;
}
