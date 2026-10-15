#pragma once

class Observer {
public:
    virtual void notify(int code) = 0;

protected:
    ~Observer() = default;
};
