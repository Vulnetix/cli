#include <iostream>
#include <string>

bool parse(const std::string &s, int &out);

int main()
{
    int i;
    int n;
    for (i = 0; i < 3; ++i) {
        std::cout << i << std::endl;
    }
    if (!parse("42", n))
        return 1;
    std::cin >> i;
    return n;
}
