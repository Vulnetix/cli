#include <iostream>
#include <string>

int main() {
    int choice;
    char confirm;
    std::string label;
    std::cin >> choice;
    std::cin >> confirm;
    std::cin >> label;
    return choice + (confirm == 'y');
}
