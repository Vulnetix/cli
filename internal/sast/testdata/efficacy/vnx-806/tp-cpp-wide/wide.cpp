#include <cstring>
#include <cwchar>

void copy(const char *s, const wchar_t *ws) {
    char out[16];
    wchar_t w[16];
~>    std::memcpy(out, s, std::strlen(s));
~>    wcsncpy(w, ws, wcslen(ws));
}
