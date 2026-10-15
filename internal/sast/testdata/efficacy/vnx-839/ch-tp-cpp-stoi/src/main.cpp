#include <iostream>
#include <string>

static const char *kNames[] = {"zero", "one", "two", "three"};

int main(int argc, char **argv)
{
    if (argc < 2) return 1;
    int i = std::stoi(argv[1]);
~>    if (i > 3) {
        std::cerr << "out of range\n";
        return 1;
    }
    std::cout << kNames[i] << "\n";
    return 0;
}
