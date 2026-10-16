#include <string>
#include <vector>

bool wants_help(const std::vector<std::string> &args)
{
    for (const std::string &a : args) {
        if (a == "--help" || a == "-h")
            return true;
    }
    return false;
}
