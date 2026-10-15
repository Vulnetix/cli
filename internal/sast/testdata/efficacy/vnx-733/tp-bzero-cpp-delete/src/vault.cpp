#include <cstring>
#include <strings.h>

void Vault::release() {
    char *masterKey = new char[64];
    load(masterKey);
    unlock(masterKey);
~>    bzero(masterKey, 64);
    delete[] masterKey;
}

void Vault::close(char *apiToken) {
~>    std::memset(apiToken, 0, 40);
    std::free(apiToken);
}
