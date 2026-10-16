#pragma once
class Point {
public:
    Point(int x, int y);
    ~Point();
    int x() const;
private:
    int x_, y_;
};
class Fwd;
// class Ghost { public: virtual void f(); ~Ghost(); };
