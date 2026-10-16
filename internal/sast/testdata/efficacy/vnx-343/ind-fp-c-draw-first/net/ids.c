#include <stdlib.h>

static unsigned long last;

unsigned long next_frame_id(void)
{
    unsigned long frame_id = rand() + last;
    last = frame_id;
    return frame_id;
}
