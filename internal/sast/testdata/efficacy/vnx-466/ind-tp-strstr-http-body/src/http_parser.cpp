#include <cstring>

namespace net {

const char *body_start(const char *response)
{
    const char *sep = strstr(response, "\r\n\r\n");
~>    return sep + 4;
}

}  // namespace net
