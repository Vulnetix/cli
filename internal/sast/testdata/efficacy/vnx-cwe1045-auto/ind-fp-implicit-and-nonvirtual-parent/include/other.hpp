#pragma once

class Base {
public:
    virtual ~Base() = default;
};

class NoDtor : public Base {
public:
    int run();
};

class Plain {
public:
    ~Plain();
};

class Derived : public Plain {
public:
    ~Derived();
};

class External : public ThirdPartyBase {
public:
    ~External();
};
