#include <cstring>
#include <string>

int read_secret(std::string &out);

int unlock(bool fail)
{
    std::string password;
    if (read_secret(password) != 0) {
        return -1;
    }
    unsigned char aes_key[32];
    if (fail) {
~>        std::memset(aes_key, 0, sizeof aes_key);
        return -2;
    }
    out_use(aes_key);
~>    std::memset(&password[0], 0, password.size());
}
