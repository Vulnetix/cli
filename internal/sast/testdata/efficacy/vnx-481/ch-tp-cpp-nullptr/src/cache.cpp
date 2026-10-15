#include "cache.h"

Entry *Cache::lookup(const std::string &key)
{
    Entry *entry = table_.find(key);
~>    if (entry = nullptr) {
        return load(key);
    }
    return entry;
}
