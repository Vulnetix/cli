#include <stdlib.h>
#include <assert.h>
#include "session.h"

static void test_session_lookup(void)
{
    struct client c;
    srand(42);
    c.session_id_num = (unsigned) rand();
    session_register(&c);
    assert(session_find(c.session_id_num) == &c);
}

int main(void)
{
    test_session_lookup();
    return 0;
}
