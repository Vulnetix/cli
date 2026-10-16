#include <windows.h>
#include <string>

class Vault {
public:
    bool Unlock(const std::string &phrase);
private:
    bool Derive(const std::string &phrase, BYTE *out, DWORD n);
    bool Open(const BYTE *k, DWORD n);
};

bool Vault::Unlock(const std::string &phrase)
{
    BYTE masterKey[32];
    if (!Derive(phrase, masterKey, sizeof(masterKey)))
        return false;
    bool opened = Open(masterKey, sizeof(masterKey));
~>    RtlZeroMemory(masterKey, sizeof(masterKey));
    return opened;
}
