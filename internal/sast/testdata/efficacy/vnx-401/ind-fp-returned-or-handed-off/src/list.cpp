#include <string>

struct Entry {
    std::string key;
    Entry *next;
};

void registry_insert(Entry *e);

Entry *make_entry(const std::string &key)
{
    Entry *e = new Entry{key, nullptr};
    return e;
}

bool add_entry(const std::string &key)
{
    Entry *e = new Entry{key, nullptr};
    registry_insert(e);
    if (key.empty()) {
        return false;
    }
    return true;
}
