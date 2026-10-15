#pragma once

struct Handler {
    virtual
    ~Handler() noexcept;
    virtual void handle() = 0;
};

struct LogHandler : Handler {
~>    ~LogHandler() noexcept;
    void handle() override;
};
