#pragma once

~>template <typename T> class Visitor {
public:
    virtual void visit(T& node) = 0;
};

~>class API_EXPORT Listener {
public:
    virtual void onEvent(int id);
    ~Listener() {}
};
