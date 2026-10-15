#include <windows.h>
#include <wchar.h>

void widen(const char narrow[64], const struct hdr *h)
{
    WCHAR wbuf[64];
    wchar_t msg[128];
    MultiByteToWideChar(CP_ACP, 0, narrow, sizeof(narrow), wbuf, ARRAYSIZE(wbuf));
    swprintf(msg, _countof(msg), L"header is %zu bytes", sizeof(*h));
    swprintf(msg, _countof(msg), L"%ls, %ls", L"a", L"b, sizeof(c)");
}
