#include <string>
#include <vector>

void add_all(std::vector<int> &items, int extra)
{
    auto it = items.begin();
    items.push_back(extra);
~>    *it = 0;
}

size_t first_after_grow(std::vector<std::string> &names)
{
    std::string &first = names.front();
    names.emplace_back("late");
~>    return first.size();
}

const char *label(std::string text)
{
    const char *raw = text.c_str();
    text += " (draft)";
~>    return raw;
}
