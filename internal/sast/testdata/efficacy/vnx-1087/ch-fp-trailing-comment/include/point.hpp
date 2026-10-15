#pragma once

class Point {
public:
    int x() const;  // deliberately not virtual
    int y() const;  /* not virtual either */
    ~Point();
};
