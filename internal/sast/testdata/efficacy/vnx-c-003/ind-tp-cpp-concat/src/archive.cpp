#include <cstdio>
#include <cstdlib>
#include <string>
#include <sstream>

int extract(const std::string &archive, const std::string &dest)
{
    std::string cmd = "tar -xzf " + archive + " -C " + dest;
~>    return std::system(cmd.c_str());
}

int list_dir(const std::string &dir)
{
~>    FILE *p = popen(("ls -la " + dir).c_str(), "r");
    if (!p)
        return -1;
    return pclose(p);
}

int convert(const std::string &input)
{
    std::ostringstream oss;
    oss << "convert " << input << " out.png";
    std::string command = oss.str();
~>    return system(command.c_str());
}
