#pragma once

class Base {
public:
    virtual ~Base() = default;
};

class A : public Base {
public:
    ~A() override;
};

class B : public Base {
public:
    virtual ~B();
};

class C final : public Base {
public:
    ~C() final = default;
};
