#include <sstream>
#include <string>

const char *user_label(const std::string &first, const std::string &last, int id)
{
    std::ostringstream out;
    out << last << ", " << first << " (#" << id << ")";
    std::string label = out.str();
~>    return label.c_str();
}
