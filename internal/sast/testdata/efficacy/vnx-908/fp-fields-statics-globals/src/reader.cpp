#include <iostream>

class Reader {
public:
    int value;
    int read()
    {
        std::cin >> value;
        return value;
    }
};

int read_one()
{
    int x;
    std::cin >> x;
    return x;
}
