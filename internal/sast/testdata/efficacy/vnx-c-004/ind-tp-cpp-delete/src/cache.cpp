#include <cstring>
#include <unordered_map>
#include <string>

struct Entry {
    size_t len;
    char *data;
};

int evict(std::unordered_map<std::string, Entry *> &cache, const std::string &key)
{
    Entry *entry = cache[key];
    cache.erase(key);
    delete[] entry->data;
    delete entry;
~>    return entry->len > 0 ? 1 : 0;
}

void reset_buffer(char *buf, size_t n)
{
    delete[] buf;
~>    std::memset(buf, 0, n);
}
