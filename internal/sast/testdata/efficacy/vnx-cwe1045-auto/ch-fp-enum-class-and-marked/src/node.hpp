#pragma once

#include <cstdint>

enum class Kind : std::uint8_t { Leaf, Branch };

class Node {
 public:
  virtual ~Node();
};

class Node;

class Leaf final : public Node {
 public:
  ~Leaf() final;
};

class Branch : public Node {
 public:
  virtual ~Branch() = default;
};

class Root : public Node {
 public:
  Root() = default;
  void add(Node* n);
};

Leaf::~Leaf() {}
