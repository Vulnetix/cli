#include <windows.h>
#include "sync.h"

void SyncDialog::ConfirmOverwrite()
{
    switch (::MessageBox(m_hWnd, _T("Overwrite the server copy with local changes?"), _T("Sync"), MB_OKCANCEL | MB_ICONQUESTION)) {
~>    case IDYES:
        m_client.PushAll(true);
        break;
    case IDCANCEL:
    default:
        break;
    }
}
