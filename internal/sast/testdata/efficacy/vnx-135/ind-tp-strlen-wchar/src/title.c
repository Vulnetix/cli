#include <string.h>
#include <wchar.h>

size_t title_length(void)
{
    const wchar_t *title = L"Settings";
~>    return strlen((const char *)title);
}
