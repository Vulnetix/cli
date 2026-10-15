#include <cstring>

namespace http {

const char *header_value(const char *line)
{
    const char *colon = std::strstr(line, ": ");
~>    return colon + 2;
}

const char *query_of(const char *url)
{
~>    return std::strchr(url, '?') + 1;
}

}  // namespace http
