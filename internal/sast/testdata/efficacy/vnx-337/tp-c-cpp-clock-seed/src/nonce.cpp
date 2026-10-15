#include <ctime>
#include <random>
#include <string>

std::string make_nonce() {
~>    std::mt19937 gen(std::time(nullptr));
    std::uniform_int_distribution<int> dist(0, 255);
    std::string out;
    for (int i = 0; i < 16; ++i) out.push_back(static_cast<char>(dist(gen)));
    return out;
}
