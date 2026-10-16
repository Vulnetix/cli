#pragma once

class Guarded {
public:
    virtual void handle();
protected:
    ~Guarded();
};
