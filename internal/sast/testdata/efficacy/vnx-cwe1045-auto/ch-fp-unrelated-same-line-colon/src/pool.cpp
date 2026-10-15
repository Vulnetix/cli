#include "pool.hpp"

class Base {
 public:
  virtual ~Base();
};

struct Options { int size; };

static const char* label(bool b) { return b ? "class Pool : public Base {" : "none"; }

class Pool {
 public:
  ~Pool();
};
