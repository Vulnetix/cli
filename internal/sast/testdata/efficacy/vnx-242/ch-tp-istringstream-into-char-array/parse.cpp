#include <sstream>
#include <string>

bool parse_header(const std::string &line) {
    std::istringstream in(line);
    char tag[8];
~>    in >> tag;
    return tag[0] == 'H';
}
