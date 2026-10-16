#include <wchar.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

void set_greeting(const wchar_t *who)
{
    wchar_t buf[64];
    wcsncpy(buf, who, sizeof(buf) / sizeof(buf[0]));
    buf[ARRAY_SIZE(buf) - 1] = L'\0';
    wchar_t tail[32];
    swprintf(tail, ARRAY_SIZE(tail), L"%ls!", who);
    show(buf);
}
