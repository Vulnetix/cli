#include "proto.h"

int handle_frame(struct frame *f)
{
    int rc;

    if (f->type == FRAME_DATA) {
        process_data(f);
    }
~>    return rc;
}
