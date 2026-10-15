#include <string>
#include <vector>

bool Registry::add(const std::string &name)
{
    auto *entry = new Entry(name);
    entries_.push_back(entry);
    if (!entry->valid()) {
        return false;
    }
    return true;
}
