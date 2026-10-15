#include <iostream>

int login() {
    char user[32];
    char pass[32];
    std::cout << "user: ";
~>    std::cin >> user;
~>    std::cin >> std::ws >> pass;
    return check(user, pass);
}
