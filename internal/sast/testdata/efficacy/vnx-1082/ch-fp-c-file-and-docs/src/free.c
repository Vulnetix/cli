#include <stdlib.h>

/* C has no delete; the word this is just a name here. */
void release(struct obj *this) {
    free(this);
}
