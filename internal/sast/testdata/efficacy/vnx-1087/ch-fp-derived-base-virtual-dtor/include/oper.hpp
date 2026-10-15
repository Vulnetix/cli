#pragma once

class AsyncOper {
public:
    virtual ~AsyncOper() noexcept = default;
    virtual void execute() = 0;
};

class IoOper : public AsyncOper {
public:
    virtual int descriptor() noexcept = 0;
    ~IoOper();
};
