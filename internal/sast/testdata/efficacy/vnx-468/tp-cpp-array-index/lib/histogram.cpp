#include <cstddef>

class Histogram {
public:
    void bump(std::size_t bucket)
    {
        int counts[64] = {0};
~>        counts[bucket * sizeof(int)] += 1;
        store(counts);
    }

    float peek(float *bins, int i)
    {
~>        return bins[i * sizeof(float)];
    }
};
