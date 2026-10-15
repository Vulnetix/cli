#include <cstddef>

class Base {
public:
    virtual ~Base() = default;
};

class Derived : public Base {
public:
    int value = 0;
};

template <typename Impl>
class Counter {
public:
    int next() { return static_cast<Impl *>(this)->step(); }
};

class Ticker : public Counter<Ticker> {
public:
    int step() { return 1; }
};

void use(Derived *d, void *ctx, std::size_t n, double ratio)
{
    Base *b = static_cast<Base *>(d);
    Derived *again = static_cast<Derived *>(ctx);
    int whole = static_cast<int>(ratio);
    char *bytes = reinterpret_cast<char *>(d);
    (void)b; (void)again; (void)whole; (void)bytes; (void)n;
}
