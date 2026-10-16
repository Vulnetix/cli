#include <cstring>
#include <string>
struct Rec { char user[16]; };
void fill(Rec &r, const std::string &user)
{
~>    std::memcpy(r.user, user.c_str(), user.size() + 1);
}
