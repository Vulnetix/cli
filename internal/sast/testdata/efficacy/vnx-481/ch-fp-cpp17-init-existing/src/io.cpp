#include <system_error>

int flush_all(Writer& w)
{
    int err;
    if (err = w.flush(); err != 0)
        return err;
    while ((err = w.next()) > 0)
        handle(err);
    return 0;
}
