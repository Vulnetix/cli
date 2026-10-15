#include <list>
#include <map>
#include <string>
#include <vector>

int keep(std::list<int> &l, std::vector<int> &v, std::vector<int> &out)
{
    auto it = l.begin();
    l.push_back(3);
    int a = *it;

    const int *p = v.data();
    out.push_back(1);
    int b = p[0];

    for (const auto &x : v)
        out.push_back(x);

    int &r = v.front();
    v.push_back(2);
    int &s = v.front();
    s = 4;
    return a + b;
}
