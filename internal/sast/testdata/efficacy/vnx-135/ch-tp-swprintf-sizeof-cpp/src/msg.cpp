#include <cwchar>

void Window::setCaption(const wchar_t *name)
{
    wchar_t buf[128];
~>    std::swprintf(buf, sizeof buf, L"%ls - Editor", name);
}
