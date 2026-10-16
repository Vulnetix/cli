#pragma once
#include <atomic>

class RefCounted {
public:
    void AddRef() { refs_.fetch_add(1, std::memory_order_relaxed); }
    void Release() {
        if (refs_.fetch_sub(1, std::memory_order_acq_rel) == 1) {
~>            delete (this);
        }
    }
protected:
    virtual ~RefCounted() = default;
private:
    std::atomic<int> refs_{1};
};
