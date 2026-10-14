#include <malloc.h>
#include <string>

void render(const std::string &title)
{
~>    char *scratch = static_cast<char *>(__builtin_alloca(title.size() + 1));
    title.copy(scratch, title.size());
}

void render_wide(const wchar_t *text, size_t chars)
{
~>    wchar_t *buf = (wchar_t *)_alloca(chars * sizeof(wchar_t));
    wmemcpy(buf, text, chars);
}
