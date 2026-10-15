#include <string>

int status_for(const std::string &kind)
{
    int code;
    if (kind == "ok") {
        code = 200;
    }
~>    return code;
}
