#include <cstring>
#include <iostream>
#include <vector>

long total_of(const std::vector<long> &xs, const char *dir)
{
    long total = 0;
    long base;
    char path[256] = "";

    base = static_cast<long>(xs.size());
    for (long x : xs) {
        total += x;
    }
    std::strcat(path, dir);
    std::cout << path << ' ' << base << '\n';
    return total;
}
