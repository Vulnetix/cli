#pragma once
class Plain {
public:
    ~Plain();
};

class Box : public Plain {
public:
    ~Box();
};

class Base2 {
public:
    virtual ~Base2();
};

class Square : public Base2 {
public:
    ~Square() override;
};
