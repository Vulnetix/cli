#include "Cache.h"

void Cache::reset() {
    delete entry_;
    if (stats_) {
        stats_->clear();
    }
~>    delete entry_;
    delete[] slots_;
    count_ = 0;
~>    delete [] slots_;
}
