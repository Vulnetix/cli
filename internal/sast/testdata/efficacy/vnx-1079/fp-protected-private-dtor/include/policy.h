#pragma once

class Observer {
public:
    virtual void update() = 0;
protected:
    ~Observer() = default;
};

class RefCounted {
    ~RefCounted();
public:
    virtual void release();
};

struct Mixin {
    virtual void apply();
protected:
    ~Mixin() {}
};
