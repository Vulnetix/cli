#include <cwchar>

void markDirty(wchar_t *title)
{
~>    title[std::wcslen(title)] = L'*';
    setWindowTitle(title);
}
