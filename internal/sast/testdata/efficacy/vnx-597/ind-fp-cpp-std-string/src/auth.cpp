#include <string>

bool is_admin(const std::string &role)
{
    return role == "admin" || role == "owner";
}

bool skip_auth(const std::string &mode)
{
    return mode != "production";
}
