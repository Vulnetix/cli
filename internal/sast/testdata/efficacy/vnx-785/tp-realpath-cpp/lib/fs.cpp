#include <climits>
#include <cstdlib>
#include <string>

std::string Canon(const std::string &p) {
  char out[512] = {0};
~>  if (::realpath(p.c_str(), out) == nullptr) {
    return {};
  }
  return std::string(out);
}
