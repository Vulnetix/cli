#pragma once
class Outer {
public:
    ~Outer();
    int size() const;
    struct Visitor {
        virtual ~Visitor() = default;
        virtual void visit(int) = 0;
    };
};
