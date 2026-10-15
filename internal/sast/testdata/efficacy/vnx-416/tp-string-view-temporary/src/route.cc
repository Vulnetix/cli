#include <string>
#include <string_view>

void route(int id, const std::string &base)
{
~>  std::string_view key = std::to_string(id);
~>  std::string_view full{std::string(base) + "/x"};
    lookup(key, full);
}
