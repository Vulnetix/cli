#include <cstring>
#include <string>

namespace text {

bool iequals(const std::string &a, const std::string &b)
{
~>    return _stricmp(a.c_str(), b.c_str()) == 0 &&
           a.size() == b.size();
}

char *duplicate(const char *s)
{
~>    char *copy = _strdup(s);
    return copy;
}

void format_id(char *out, std::size_t n, int id)
{
~>    sprintf_s(out, n, "id-%d", id);
}

}  // namespace text
