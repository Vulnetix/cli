#include <wchar.h>

void set_greeting(const wchar_t *who)
{
    wchar_t buf[64];
~>    wcsncpy(buf, who, sizeof(buf));
    buf[63] = L'\0';
    show(buf);
}
