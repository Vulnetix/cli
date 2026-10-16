#include <string>
struct Widget { int id; };
Widget *lookup(const std::string &h)
{
~>    auto *obj = reinterpret_cast<Widget *>(std::stoull(h));
    return obj;
}
