#include <algorithm>
#include <vector>

struct Item { int id; unsigned flags; };

bool has(const std::vector<Item> &items, int id)
{
    return std::any_of(items.begin(), items.end(), [&](const Item& item) { return item.id == id; });
}

bool operator==(const Item& a, const Item& b) { return a.id == b.id; }

bool flagged(const Item &it, unsigned mask)
{
    return (it.flags & mask) == mask;
}
