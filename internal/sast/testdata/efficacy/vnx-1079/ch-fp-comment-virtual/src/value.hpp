#pragma once

class Value {
public:
    // virtual void hook();
    /* virtual void other(); */
    int get() const { return v_; }
private:
    int v_ = 0;
};
