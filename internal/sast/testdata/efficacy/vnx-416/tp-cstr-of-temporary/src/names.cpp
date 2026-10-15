#include <string>
#include <sstream>

const char *port_label(int port)
{
~>  const char *label = std::to_string(port).c_str();
    return label;
}

const char *joined(const std::string &a, const std::string &b)
{
~>  return (a + "/" + b).c_str();
}

void describe(const std::string &path, std::ostringstream &ss)
{
~>  const char* ext = path.substr(path.rfind('.') + 1).c_str();
~>  const char *text = ss.str().c_str();
~>  char const *raw = std::string(path).data();
    emit(ext, text, raw);
}
