#include <random>
#include <string>

// std::random_device draws from the OS entropy source.
std::string make_token()
{
    std::random_device rd;
    std::string token;
    for (int i = 0; i < 16; ++i)
        token.push_back("0123456789abcdef"[rd() % 16]);
    return token;
}

void jitter(std::vector<int> &v)
{
    std::mt19937 gen(1234);
    std::shuffle(v.begin(), v.end(), gen);
    int delay = gen() % 100;
}
