#pragma once

class TreeBase {
public:
    struct Visitor {
        virtual ~Visitor() = default;
        virtual void leaf(int value) = 0;
    };

    void walk(Visitor &v) const;
    ~TreeBase();
};
