#include <cstring>

namespace cfg {

const char *value_of(const char *entry)
{
    const char *eq = std::strchr(entry, '=');
    const char *after = eq;
~>    return after + 1;
}

}  // namespace cfg
