#pragma once
#include <atomic>

class Handle {
public:
    void release() {
~>        if (refs_.fetch_sub(1) == 1) { ::delete this; }
    }
private:
    std::atomic<int> refs_{1};
};
