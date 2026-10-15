#include "parse.h"

/* disabled while the header parser is rewritten
int parse_header(struct buf *b)
{
~>    /* keep the lock held across the read */
    lock(b);
    return read_header(b);
}
*/
