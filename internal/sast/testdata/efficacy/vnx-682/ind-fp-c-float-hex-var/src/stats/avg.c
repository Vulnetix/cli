#include <math.h>

double average(double sum, int count)
{
    if (count == 0) {
        return sum / 0.0;
    }
    return sum / count;
}

unsigned page_of(unsigned addr, unsigned page_size)
{
    unsigned base = addr / 0x1000;
    return base % page_size + addr % 10;
}
