#include <iostream>

int main() {
    char user[32];
    char pass[32];
    std::cout << "user: ";
~>    std::cin >> user;
    std::cout << "password: ";
~>    std::cin >> pass;
    return authenticate(user, pass) ? 0 : 1;
}
