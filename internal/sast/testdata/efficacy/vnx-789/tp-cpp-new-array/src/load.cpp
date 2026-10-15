#include <string>

void Load(const std::string &arg) {
  int cells = std::stoi(arg);
~>  auto *grid = new int[cells];
  delete[] grid;
}
