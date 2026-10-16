#pragma once
class Observer {
public:
    virtual void notify() = 0;
protected:
    ~Observer() = default;
};
class Leaf final {
public:
    virtual void go();
    ~Leaf();
};
class Impl : public Observer {
public:
    void notify() override;
    ~Impl();
};
