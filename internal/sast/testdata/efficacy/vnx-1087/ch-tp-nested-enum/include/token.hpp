#pragma once

~>class Token {
public:
    enum class Kind {
        Ident,
        Number,
    };
    struct Span {
        int begin;
        int end;
    };
    virtual Kind kind() const = 0;
    virtual Span span() const;
    ~Token();
};
