#include <windows.h>

void wipe(HWND owner)
{
    int r = MessageBox(owner, "Wipe the vault?", "Vault", MB_OKCANCEL);
~>    if (r == IDYES) {
        wipe_vault();
    }
}
