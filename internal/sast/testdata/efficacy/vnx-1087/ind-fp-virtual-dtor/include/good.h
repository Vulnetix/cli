#pragma once

class Good {
public:
    virtual void handle();
    virtual ~Good();
};

class AlsoGood {
public:
    virtual ~AlsoGood() = default;
    virtual int size() const = 0;
};
