#include "codec.hpp"

class Base {
public:
    virtual ~Base() = default;
};

class FakeCodec : public Base {
public:
    ~FakeCodec() {}
};
