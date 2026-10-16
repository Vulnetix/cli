#pragma once

class Handle {
public:
    Handle() : r_(new int(0)) {}
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    ~Handle() { delete r_; }
private:
    int* r_;
};

class Mover {
public:
    Mover() : r_(new int(1)) {}
    Mover(Mover&& o) noexcept : r_(o.r_) { o.r_ = nullptr; }
    ~Mover() { delete r_; }
private:
    int* r_;
};

class Widget {
    Q_DISABLE_COPY(Widget)
public:
    ~Widget() { delete d_; }
private:
    int* d_;
};
