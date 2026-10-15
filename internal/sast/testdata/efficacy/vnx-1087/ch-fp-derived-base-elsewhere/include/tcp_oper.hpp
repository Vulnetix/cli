#pragma once
#include "async_oper.hpp"

class TcpOper : public AsyncOper {
public:
    virtual int descriptor() noexcept = 0;
    virtual bool advance() noexcept = 0;
};
