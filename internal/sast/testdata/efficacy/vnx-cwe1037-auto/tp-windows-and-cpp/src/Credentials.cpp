#include <windows.h>
#include <array>
#include <cstring>
#include <string>

#include "Vault.h"

BOOL PromptAndStore(HWND owner)
{
    TCHAR szPassword[256];
    SEC_WINNT_AUTH_IDENTITY cred;

    if (!PromptForPassword(owner, szPassword, ARRAYSIZE(szPassword)))
        return FALSE;
    BuildIdentity(&cred, szPassword);
    BOOL stored = StoreIdentity(&cred);
~>    RtlZeroMemory(&cred, sizeof(cred));
~>    ZeroMemory(szPassword, sizeof(szPassword));
    return stored;
}

bool Vault::unlock(const std::string& pin)
{
    std::array<uint8_t, 32> master_key{};
    derive(pin, master_key.data());
    bool ok = verify(master_key.data());
~>    std::memset(master_key.data(), 0, master_key.size());
    return ok;
}
