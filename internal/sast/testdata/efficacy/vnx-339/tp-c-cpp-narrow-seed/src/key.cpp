#include <random>
#include <string>

std::string make_secret_key(unsigned id) {
~>    std::mt19937 gen(id % 65536);
    return std::to_string(gen());
}
