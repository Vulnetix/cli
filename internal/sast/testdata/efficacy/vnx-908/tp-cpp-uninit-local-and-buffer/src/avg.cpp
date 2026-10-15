#include <cstring>
#include <vector>

double average(const std::vector<double> &v)
{
    double sum;
    for (double x : v)
~>        sum += x;
    return v.empty() ? 0 : sum / v.size();
}

char *copy_name(const char *src)
{
    char *dst = new char[64];
~>    std::strcat(dst, src);
    return dst;
}
