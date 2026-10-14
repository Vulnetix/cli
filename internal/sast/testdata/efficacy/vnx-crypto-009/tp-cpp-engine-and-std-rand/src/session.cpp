#include <cstdlib>
#include <random>
#include <string>

class SessionStore {
    std::mt19937_64 rng_{std::random_device{}()};

public:
    std::string issue();
};

std::string SessionStore::issue()
{
    static const char chars[] = "0123456789abcdef";
    std::uniform_int_distribution<int> pick(0, 15);
    std::string sessionToken;
    for (int i = 0; i < 32; ++i)
~>        sessionToken += chars[pick(rng_)];
    return sessionToken;
}

unsigned int make_nonce()
{
    std::default_random_engine gen(42);
~>    return static_cast<unsigned int>(gen());
}

void seed_cookie(std::string &cookie)
{
~>    cookie = std::to_string(std::rand());
}
