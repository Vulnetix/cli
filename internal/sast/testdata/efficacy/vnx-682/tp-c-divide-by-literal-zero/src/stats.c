#include <stdio.h>

int ratio(int hits, int total) {
    if (total == 0) {
~>        return hits / 0;
    }
~>    int rem = hits % 0;
    int x = hits;
~>    x /= 0;
~>    return (hits * 100)/0 + rem + x;
}
