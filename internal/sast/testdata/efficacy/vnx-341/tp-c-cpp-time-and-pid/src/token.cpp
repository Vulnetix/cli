#include <ctime>
#include <string>

std::string make_token() {
~>    return std::to_string(std::time(nullptr));
}
