#include "compat.h"

void Reader::run() {
    line = conn.gets(buf, 64);
    line = conn->gets(buf, 64);
    budgets(total);
}
