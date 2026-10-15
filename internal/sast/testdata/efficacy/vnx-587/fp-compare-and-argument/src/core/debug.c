#include <assert.h>

int is_marker(void *child)
{
    register_cb(on_done, (void *)0x12345678);
    assert(child != (void*)0x65d1760);
    return child == (void *)0x40020000;
}
