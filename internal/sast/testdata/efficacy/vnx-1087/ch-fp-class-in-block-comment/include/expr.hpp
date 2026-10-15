#pragma once

/*
Design notes. The accessor used to be declared as

class Accessor {
public:
    virtual double get(int row) const;
};

and was replaced by the template below.
*/
template <typename T>
class TypedAccessor {
public:
    T get(int row) const;
};
