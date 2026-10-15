#include <vector>

double mean(const std::vector<double> &v, char **argv)
{
    int scale = atoi(argv[1]);
    double sum = 0;
    for (double x : v)
        sum += x;
    const char *note = "sum / scale";
    return sum / v.size() * scale;
}
