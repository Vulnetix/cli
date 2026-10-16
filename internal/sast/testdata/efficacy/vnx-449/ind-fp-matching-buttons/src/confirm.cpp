#include <windows.h>
#include <QMessageBox>

bool confirmWipe(HWND hwnd)
{
    int r = MessageBoxW(hwnd, L"Wipe local cache?", L"Confirm", MB_YESNO | MB_ICONWARNING);
    return r == IDYES;
}

void SettingsPage::onPurge()
{
    if (QMessageBox::question(this, tr("Purge"), tr("Purge all audit logs?")) == QMessageBox::Yes)
        m_audit->purge();
}
