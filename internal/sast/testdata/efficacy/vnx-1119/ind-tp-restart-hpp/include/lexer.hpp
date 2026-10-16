#pragma once
#include <string>

inline int skip_ws(std::istream &in)
{
top:
    int c = in.get();
    if (c == ' ' || c == '\t') {
~>        goto top;
    }
    return c;
}
