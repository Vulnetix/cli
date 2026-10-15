#include <list>
#include <vector>

void add_all(std::vector<int> &items, int extra)
{
    items.reserve(items.size() + 1);
    items.push_back(extra);
    auto it = items.begin();
    *it = 0;
}

void reset(std::vector<int> &items, int extra)
{
    auto it = items.begin();
    items.push_back(extra);
    it = items.begin();
    *it = 1;
}

void prune(std::vector<int> &items)
{
    auto it = items.begin();
    while (it != items.end()) {
        if (*it < 0)
            it = items.erase(it);
        else
            ++it;
    }
}

void link_all(std::list<int> &nodes)
{
    auto pos = nodes.begin();
    nodes.push_back(4);
    *pos = 3;
}

int sum(const std::vector<int> &values)
{
    int total = 0;
    for (const auto &v : values) {
        total += v;
    }
    return total;
}
