#include <string>
#include <string_view>

std::string_view route_key(std::string_view method, std::string_view path)
{
    std::string key;
    key.reserve(method.size() + path.size() + 1);
    key.append(method).append(" ").append(path);
~>    return key;
}
