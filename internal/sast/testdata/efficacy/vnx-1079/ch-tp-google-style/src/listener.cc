#include <string>

namespace net {

~>class Listener {
 public:
  Listener();
  ~Listener();

  virtual void OnOpen(const std::string& peer);
  virtual void OnClose(int code);

 private:
  int count_ = 0;
};

Listener::Listener() {}
Listener::~Listener() {}

}  // namespace net
