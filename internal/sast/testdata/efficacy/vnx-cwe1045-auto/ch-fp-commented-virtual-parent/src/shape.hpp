#pragma once

class Shape {
 public:
  // virtual ~Shape();  removed: shapes are never deleted through a base pointer
  ~Shape();
  int sides() const;
};

class Square : public Shape {
 public:
  ~Square();
};
