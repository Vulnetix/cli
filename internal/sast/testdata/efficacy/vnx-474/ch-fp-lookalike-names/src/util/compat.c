#include <stdlib.h>

int my_vfork_count(void);
void *xrealloc0(void *p);

struct handler_table { void (*signal)(int); };

int count(void)
{
    int signals = 0;
    signals += my_vfork_count();
    return signals;
}
