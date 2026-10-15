#include <string>
#include <vector>

void append_name(const std::string &suffix)
{
    std::string *name;
~>    name->append(suffix);
}

size_t count_items()
{
    std::vector<int> *items;
~>    return items->size();
}
