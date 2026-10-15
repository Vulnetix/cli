#include <random>
#include <string>

std::string make_token() {
~>    std::mt19937 gen(42);
    std::uniform_int_distribution<int> dist(0, 15);
    std::string out;
    for (int i = 0; i < 32; ++i) out.push_back("0123456789abcdef"[dist(gen)]);
    return out;
}
