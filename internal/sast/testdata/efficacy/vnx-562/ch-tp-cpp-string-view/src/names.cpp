#include <string>
#include <string_view>

std::string_view display_name(const std::string& first, const std::string& last)
{
    std::string full = first + " " + last;
~>    return full;
}

std::string display_name_owned(const std::string& first, const std::string& last)
{
    std::string full = first + " " + last;
    return full;
}
