#include <memory>
#include <boost/noncopyable.hpp>

#define DISALLOW_COPY_AND_ASSIGN(T) T(const T&) = delete; void operator=(const T&) = delete

class Pool : private boost::noncopyable {
public:
    Pool() : slots_(new int[64]) {}
    ~Pool() { delete[] slots_; }

private:
    int* slots_;
};

class Cache {
public:
    Cache() : table_(new int[16]) {}
    ~Cache() {
        delete[] table_;
    }

private:
    DISALLOW_COPY_AND_ASSIGN(Cache);
    int* table_;
};

class Owner {
public:
    Owner() : p_(std::make_unique<int>(1)) {}
    ~Owner() = default;

private:
    std::unique_ptr<int> p_;
};
