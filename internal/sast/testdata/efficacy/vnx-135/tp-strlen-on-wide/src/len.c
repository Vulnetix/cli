#include <string.h>
#include <wchar.h>

size_t width(void)
{
    const wchar_t *title = L"Grüße";
~>    return strlen((const char *)title);
}
