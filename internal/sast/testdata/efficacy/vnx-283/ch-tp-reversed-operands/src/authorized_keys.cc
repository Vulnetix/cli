#include <sys/stat.h>
#include <string>

bool KeysFileTrusted(const std::string &file) {
  struct stat s;
  if (stat(file.c_str(), &s) < 0) {
    return false;
  }
~>  return (S_IWOTH & s.st_mode) == 0;
}
