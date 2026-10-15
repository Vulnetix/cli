#include <cstddef>

bool in_bounds(const char *cursor, const char *end, size_t len) {
~>    if (cursor + len < cursor) {
        return false;
    }
    return cursor + len <= end;
}
