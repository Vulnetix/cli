#include <stdio.h>

void dispatch(struct request *req)
{
    int mode;

~>    switch (mode) {
    case 0:
        handle_read(req);
        break;
    default:
        handle_write(req);
    }
}
