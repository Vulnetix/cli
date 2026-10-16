#include "ring.h"

int lane_for(unsigned seq)
{
    int lane;

    switch (seq % 4) {
    case 0: lane = 3; break;
    case 1: lane = 1; break;
    case 2: lane = 0; break;
    case 3: lane = 2; break;
    }
    return lane;
}
