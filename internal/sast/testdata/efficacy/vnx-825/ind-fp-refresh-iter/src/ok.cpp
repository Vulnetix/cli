#include <vector>
#include <list>
#include <map>

void h(std::vector<int> &v, std::list<int> &l, std::map<int,int> &m)
{
    for (auto it = v.begin(); it != v.end();) {
        if (*it == 0) it = v.erase(it);
        else ++it;
    }
    auto li = l.begin();
    l.push_back(3);
    *li = 1;
    auto mi = m.begin();
    m[5] = 6;
    mi->second = 2;
    auto it2 = v.begin();
    v.push_back(1);
    it2 = v.begin();
    *it2 = 4;
    // *out = &value;
    const char *s = "*out = &value;";
    (void)s;
}
