#include <vector>
// Do not write: int n = atoi(s); char *p = malloc(n);
void f()
{
    std::vector<int> v(10);
    const char *doc = "n = atoi(x); buf = malloc(n)";
    (void)doc; (void)v;
}
