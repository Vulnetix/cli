#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <string>

int extract(const std::string &archive, const std::string &dest)
{
    std::string cmd = "tar -xf " + archive + " -C " + dest;
~>    return std::system(cmd.c_str());
}

int list(const std::string &dir)
{
~>    FILE *p = popen(("ls " + dir).c_str(), "r");
    return pclose(p);
}

int remove_user(const std::string &name)
{
    std::ostringstream oss;
    oss << "userdel " << name;
~>    return system(oss.str().c_str());
}

int chown_file(const std::string &owner, const std::string &path)
{
    std::string cmd("chown ");
    cmd += owner;
    cmd.append(" ").append(path);
~>    return system(cmd.c_str());
}
