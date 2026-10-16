#include <windows.h>
#include <cstring>
#include <string>

void BuildShortcutTarget(wchar_t *target, const wchar_t *folder, const wchar_t *file)
{
~>    wcscpy(target, folder);
    wcscat(target, L"\\");
~>    wcscat(target, file);
}

void CopyAnsiTitle(LPSTR dest, LPCSTR title)
{
~>    lstrcpyA(dest, title);
}

void CopyName(char *dst, const std::string &name)
{
~>    std::strcpy(dst, name.c_str());
}
