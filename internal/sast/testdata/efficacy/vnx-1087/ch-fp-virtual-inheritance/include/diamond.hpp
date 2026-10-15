#pragma once

class Left : virtual public Base {
public:
    void left();
    int value() const;
};

class Right : public virtual Base {
public:
    void right();
};
