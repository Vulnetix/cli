#include <cstring>

void Vault::open(const std::string &name)
{
    char *secret = new char[32];
    load_secret(name, secret, 32);
    use(secret);
~>    memset(secret, 0, 32);
    delete[] secret;
}
