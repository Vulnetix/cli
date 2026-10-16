#include <sstream>
#include <string>
#include <string_view>
#include <QString>

const char *config_path(const std::string &dir, const std::string &name)
{
~>    const char *path = (dir + "/" + name).c_str();
    return path;
}

void describe(int code, std::ostringstream &oss, const std::string &line, const QString &msg)
{
~>    const char *text = oss.str().c_str();
~>    const char *prefix = line.substr(0, 4).c_str();
~>    const char *raw = msg.toUtf8().data();
~>    std::string_view sv = std::string(line.begin(), line.end());
    emit(text, prefix, raw, sv);
}

const char *code_name(int code)
{
~>    return std::to_string(code).c_str();
}
