#include <malloc.h>
#include <string>
#include <cwchar>

void set_title(const std::string &title)
{
~>    char *scratch = static_cast<char *>(__builtin_alloca(title.size() + 1));
    title.copy(scratch, title.size());
    scratch[title.size()] = '\0';
}

void widen(const char *src, size_t chars)
{
~>    wchar_t *buf = (wchar_t *)_alloca(chars * sizeof(wchar_t));
    mbstowcs(buf, src, chars);
}
