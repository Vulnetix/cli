#pragma once
#include <atomic>

class RefCounted {
public:
    void AddRef() { ++refs_; }
    void Release() {
~>        if (--refs_ == 0) delete this;
    }

protected:
    virtual ~RefCounted() = default;

private:
    std::atomic<int> refs_{1};
};
