#include <map>
#include <sstream>
#include <string>

void report(const std::map<int, std::string> &m, std::ostringstream &out)
{
    std::string body = out.str();
    const char *text = body.c_str();
    for (auto it = m.begin(); it != m.end(); ++it) {
        const char *name = it->second.c_str();
        emit(text, name);
    }
    // const char *bad = std::to_string(1).c_str();
    const char *doc = "call std::to_string(n).c_str() only inside one expression";
    emit(doc, nullptr);
}
